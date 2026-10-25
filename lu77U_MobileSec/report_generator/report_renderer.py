#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.report_renderer

Purpose:
    Render a report from the exported JSON result, so that a stored scan can be re-rendered without re-running the analysis.

Responsibilities:
    Adapt the JSON shape back to the objects the HTML builder expects, flatten the findings, and render.

Dependencies:
    The comprehensive HTML builder.

Implementation notes:
    The builder was written against the live detection objects, and the JSON export is a flattened view of them. Rather than rewrite the builder to accept both, small shim objects present the JSON with the attribute names it already reads. That keeps one rendering path for live and stored results, which is what stops a re-rendered report differing from the original.
"""

from typing import Any, Dict, List

from .comprehensive_html_builder import ComprehensiveHTMLBuilder

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_NA = {None, "", "N/A", "n/a", "Unknown", "unknown"}

def _clean(value: Any) -> Any:
    """
    Purpose:
        Normalise placeholder values back to absent.

    Parameters:
        value: The stored value.

    Returns:
        None for a placeholder, the value otherwise.

    Implementation notes:
        The export writes placeholders where a value was unknown, and the builder distinguishes absent from present. Without this, a report re-rendered from JSON would display the placeholder text as though it were the app's real package name.
    """
    return None if value in _NA else value

class _BasicInfoShim:
    """
    Purpose:
        Presents exported application information with the attribute names the HTML builder reads.

    Attributes:
        app_name, package_name, version_name, version_code, min_sdk, target_sdk, file_type: The exported values, with placeholders normalised to None.

    Thread-safety:
        Immutable after construction.
    """
    def __init__(self, app: Dict[str, Any]):
        """
        Purpose:
            Build the shim from the exported application section.

        Parameters:
            app: The exported application information.
        """
        self.app_name = _clean(app.get("app_name"))
        self.package_name = _clean(app.get("package_name"))
        self.version_name = _clean(app.get("version_name"))
        self.version_code = _clean(app.get("version_code"))
        self.min_sdk = _clean(app.get("min_sdk"))
        self.target_sdk = _clean(app.get("target_sdk"))
        self.file_type = _clean(app.get("file_type"))
        fs = app.get("file_size")
        self.file_size = fs if isinstance(fs, (int, float)) else None
        self.activities = app.get("activities") or []
        self.services = app.get("services") or []
        self.receivers = app.get("receivers") or []
        self.providers = app.get("providers") or []

    def get_file_size_formatted(self) -> str:
        """
        Purpose:
            Render the exported file size with the unit a reader would use.

        Returns:
            A formatted size string; zero bytes when the export carried no size.

        Implementation notes:
            Present because the HTML builder calls this method on the live result object, and the shim has to offer the same surface. The scaling mirrors the live result type's own formatting, so a report re-rendered from JSON shows the same size string as the original. That duplication is deliberate: importing the live type here would pull the detection package into the renderer for one method.
        """
        fs = self.file_size or 0
        if fs < 1024:
            return f"{fs} bytes"
        if fs < 1024 * 1024:
            return f"{fs / 1024:.1f} KB"
        if fs < 1024 * 1024 * 1024:
            return f"{fs / (1024 * 1024):.1f} MB"
        return f"{fs / (1024 * 1024 * 1024):.1f} GB"

class _FrameworkResultsShim:
    """
    Purpose:
        Presents exported framework detection with the attribute names the HTML builder reads.

    Attributes:
        detected_frameworks: Normalised detections with name and confidence.

    Implementation notes:
        Framework entries are read under either of two key spellings, because the export format has used both.

    Thread-safety:
        Immutable after construction.
    """
    def __init__(self, fw: Dict[str, Any]):
        """
        Purpose:
            Build the shim from the exported framework section.

        Parameters:
            fw: The exported framework detection.
        """
        self._primary = fw.get("primary_framework") or "Unknown"
        self.detected_frameworks = [
            {"framework": (f.get("name") or f.get("framework") or "Unknown"),
             "confidence": f.get("confidence", 0) or 0}
            for f in (fw.get("frameworks") or [])
        ]

    def get_primary_framework_name(self) -> str:
        """
        Purpose:
            Name the primary framework, as the HTML builder expects to ask.

        Returns:
            The framework name, or a placeholder when detection found none.

        Implementation notes:
            Matches the method the builder calls on the live framework result, so one rendering path serves both live and re-rendered reports.
        """
        return self._primary

class _DetectionResultShim:
    """
    Purpose:
        Presents an exported result with the attribute names the HTML builder reads.

    Attributes:
        target_path: The analysed target.
        basic_info: Application information shim, or None.
        framework_results: Framework detection shim, or None.

    Implementation notes:
        The application shim is only built when the export actually carries identity, so a scan that could not read the package renders as unknown rather than as a row of placeholders.

    Thread-safety:
        Immutable after construction.
    """
    def __init__(self, result: Dict[str, Any]):
        """
        Purpose:
            Build the shim from an exported result.

        Parameters:
            result: The exported result.
        """
        app = result.get("application_info") or {}
        self.target_path = (result.get("metadata") or {}).get("target")
        self.basic_info = (_BasicInfoShim(app)
                           if _clean(app.get("package_name")) or _clean(app.get("app_name"))
                           else None)
        fw = result.get("framework_detection") or {}
        self.framework_results = _FrameworkResultsShim(fw) if fw else None

def _flatten_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Produce a flat finding list from an export that may group them by severity.

    Parameters:
        result: The exported result.

    Returns:
        The findings in severity order.

    Implementation notes:
        Both export shapes are handled: a flat list is returned as-is, and a severity-keyed mapping is flattened in severity order so the report's ordering matches a live render. Unrecognised severity keys are appended after the known ones rather than dropped, so a finding under an unexpected severity still reaches the report.
    """
    vulns = (result.get("vulnerability_analysis") or {}).get("vulnerabilities")
    if isinstance(vulns, list):
        return vulns
    if isinstance(vulns, dict):
        out: List[Dict[str, Any]] = []
        for sev in _SEV_ORDER:
            out.extend(vulns.get(sev, []) or [])
        for key, items in vulns.items():
            if key not in _SEV_ORDER and isinstance(items, list):
                out.extend(items)
        return out
    return []

def render_report_html(result: Dict[str, Any]) -> str:
    """
    Purpose:
        Render an HTML report from an exported JSON result.

    Parameters:
        result: The exported result.

    Returns:
        The report HTML.

    Implementation notes:
        Goes through the same builder as a live render, so a re-rendered report is identical to the original rather than a second implementation that can drift. A missing analysis section defaults to success, since an export that reached this point completed. The analyzer details and the analysis alias are merged, details first: the alias carries the dashboard's names (supported, success) but not the coverage block or the limitation, and reading the alias alone once left every downloaded report without its incomplete-analysis notice.

    Security considerations:
        The exported result contains attacker-derived strings from the APK. Escaping is the builder's responsibility and applies identically on this path.
    """
    result = result or {}
    detection_result = _DetectionResultShim(result)
    vulnerability_results = {
        "vulnerabilities": _flatten_findings(result),
        "analysis_success": bool((result.get("analysis") or {}).get("success", True)),
    }
    analyzer_results: Dict[str, Any] = {
        **(result.get("analyzer_details") or {}), **(result.get("analysis") or {})}
    return ComprehensiveHTMLBuilder(verbose=False).build_comprehensive_report(
        detection_result, vulnerability_results, analyzer_results)
