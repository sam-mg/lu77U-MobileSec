"""On-demand report renderer."""

from typing import Any, Dict, List, Optional

from .comprehensive_html_builder import ComprehensiveHTMLBuilder

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_NA = {None, "", "N/A", "n/a", "Unknown", "unknown"}

def _clean(value: Any) -> Any:
    return None if value in _NA else value

class _BasicInfoShim:
    """Mimics ``DetectionResult.basic_info`` for the HTML builder, from
    ``result.json``'s ``application_info`` block."""

    def __init__(self, app: Dict[str, Any]):
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
        fs = self.file_size or 0
        if fs < 1024:
            return f"{fs} bytes"
        if fs < 1024 * 1024:
            return f"{fs / 1024:.1f} KB"
        if fs < 1024 * 1024 * 1024:
            return f"{fs / (1024 * 1024):.1f} MB"
        return f"{fs / (1024 * 1024 * 1024):.1f} GB"

class _FrameworkResultsShim:
    """Mimics ``DetectionResult.framework_results`` for the HTML builder, from
    ``result.json``'s ``framework_detection`` block."""

    def __init__(self, fw: Dict[str, Any]):
        self._primary = fw.get("primary_framework") or "Unknown"
        self.detected_frameworks = [
            {"framework": (f.get("name") or f.get("framework") or "Unknown"),
             "confidence": f.get("confidence", 0) or 0}
            for f in (fw.get("frameworks") or [])
        ]

    def get_primary_framework_name(self) -> str:
        return self._primary

class _DetectionResultShim:
    """The minimal ``DetectionResult`` surface the HTML builder touches."""

    def __init__(self, result: Dict[str, Any]):
        app = result.get("application_info") or {}
        self.target_path = (result.get("metadata") or {}).get("target")
        self.basic_info = (_BasicInfoShim(app)
                           if _clean(app.get("package_name")) or _clean(app.get("app_name"))
                           else None)
        fw = result.get("framework_detection") or {}
        self.framework_results = _FrameworkResultsShim(fw) if fw else None

def _flatten_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Findings as the flat list the builder expects, from either the by-severity
    dict (``result.json``) or a plain list."""
    vulns = (result.get("vulnerability_analysis") or {}).get("vulnerabilities")
    if isinstance(vulns, list):
        return vulns
    if isinstance(vulns, dict):
        out: List[Dict[str, Any]] = []
        for sev in _SEV_ORDER:
            out.extend(vulns.get(sev, []) or [])
        for key, items in vulns.items():          # any unexpected buckets too
            if key not in _SEV_ORDER and isinstance(items, list):
                out.extend(items)
        return out
    return []

def render_report_html(result: Dict[str, Any]) -> str:
    """Return the comprehensive HTML report for ``result`` (result.json),
    identical in format to the report generated at scan time — produced by the
    same :class:`ComprehensiveHTMLBuilder`, fed from the stored JSON."""
    result = result or {}
    detection_result = _DetectionResultShim(result)
    vulnerability_results = {
        "vulnerabilities": _flatten_findings(result),
        "analysis_success": bool((result.get("analysis") or {}).get("success", True)),
    }
    analyzer_results: Optional[Dict[str, Any]] = (
        result.get("analysis") or result.get("analyzer_details") or {})
    return ComprehensiveHTMLBuilder(verbose=False).build_comprehensive_report(
        detection_result, vulnerability_results, analyzer_results)