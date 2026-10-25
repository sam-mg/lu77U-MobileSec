#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.dart_tls

Purpose:
    Find Dart code that switches off TLS certificate validation on an HttpClient, in a Flutter app's own code.

Responsibilities:
    Read the app's own Dart -- Blutter's disassembly of its packages in a release build, its recovered source in a debug build -- and emit a finding where a badCertificateCallback that always accepts is installed.

Dependencies:
    re, pathlib, the Flutter recovery helpers, the kernel extractor's directory name.

Implementation notes:
    Dart networking ignores the Android trust store and the platform's network security config, so a Java scanner never sees this, and in a release build the setter's name does not survive either: `client.badCertificateCallback = (cert, host, port) => true` compiles to an allocation of Dart's shared always-true closure, Object::_simpleInstanceOfTrue, stored into a field of the _HttpClient the same function just built. That pair is what is matched in the disassembly; in recovered source the assignment is matched directly. A real scan read the function five times and never reported it, because nothing in the disassembly said "certificate". Only the app's own packages are read, so a plugin's internals cannot produce a finding. The title names only what the disassembly shows (HttpClient), not the setter: the API-claim gate refutes a title naming an API the cited code lacks, and it refuted this rule's own finding when the title said badCertificateCallback.
"""

import re
from pathlib import Path
from typing import List

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_ALWAYS_TRUE_CLOSURE = "Object::_simpleInstanceOfTrue"
_HTTP_CLIENT_MARKER = "_HttpClient"
_LOOKBACK_LINES = 40
_SOURCE_RE = re.compile(
    r"badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true\b|\{\s*return\s+true\s*;\s*\})")


def _app_files(root: Path) -> List[Path]:
    """
    Purpose:
        List the app's own Dart files in either build mode.

    Parameters:
        root: The Flutter analysis root.

    Returns:
        The app packages' disassembly files, or the recovered app source.

    Implementation notes:
        The Flutter helpers are imported here rather than at module load, because the rule engine is imported while the analyzers package is still initialising.
    """
    from ...flutter import recovered
    from ....decompiler.dart_kernel import APP_DIR
    files: List[Path] = []
    asm_dir = root / "asm"
    if asm_dir.is_dir():
        groups = recovered.asm_packages(asm_dir)
        for package in sorted(recovered.find_app_packages(groups)):
            files += sorted(groups.get(package, []))
    source_dir = root / APP_DIR
    if source_dir.is_dir():
        files += sorted(source_dir.rglob("*.dart"))
    return files


def _finding(rel: str, line: int, how: str) -> SastFinding:
    """
    Purpose:
        Build the finding for one accepting callback.

    Parameters:
        rel: The file, relative to the analysis root.
        line: The 1-based line.
        how: What was matched, for the description.

    Returns:
        The finding.
    """
    return SastFinding(
        title="Dart HttpClient accepts every TLS certificate",
        severity="High", vuln_class="NETWORK-01", file=rel, line=line, detector="dart-tls",
        confidence="MEDIUM",
        description=("An HttpClient in the app's own Dart code is given a badCertificateCallback that "
                     f"returns true ({how}), so any certificate is accepted for that client's requests."),
        impact=("An attacker on the network path presents their own certificate and reads or modifies "
                "the traffic; Dart does not use the Android trust store, so no device setting restores "
                "validation."),
        recommendation=("Remove the callback, or validate the certificate it is given against a pinned "
                        "fingerprint and return true only on a match."),
        cwe="CWE-295", owasp_mobile="M5: Insecure Communication")


def analyze_dart_tls(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Report every always-accepting badCertificateCallback in the app's own Dart code.

    Parameters:
        source_root: The Flutter analysis root.
        verbose: Traces the outcome.

    Returns:
        The findings.

    Side effects:
        Reads the app's Dart files.

    Implementation notes:
        In disassembly the always-true closure is matched only when the same function built an _HttpClient within the preceding lines, which is what ties a generic `=> true` closure to the certificate callback rather than to, say, a list filter.
    """
    root = Path(source_root)
    out: List[SastFinding] = []
    for path in _app_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix == ".dart" and "/asm/" not in f"/{rel}":
            text = "\n".join(lines)
            for match in _SOURCE_RE.finditer(text):
                out.append(_finding(rel, text[:match.start()].count("\n") + 1, "assigned in source"))
            continue
        for index, line in enumerate(lines):
            if _ALWAYS_TRUE_CLOSURE not in line:
                continue
            window = lines[max(0, index - _LOOKBACK_LINES):index]
            if any(_HTTP_CLIENT_MARKER in earlier for earlier in window):
                out.append(_finding(rel, index + 1,
                                    "Dart's shared always-true closure stored into a freshly built _HttpClient"))
    verbose_print(f"SAST dart-tls: {plural(len(out), 'finding')}", verbose)
    return out
