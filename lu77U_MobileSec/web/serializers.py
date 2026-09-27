#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.serializers

Purpose:
    Shape a completed scan into the JSON the dashboard and the stored result share, so that what the browser renders and what is written to disk are the same document.

Responsibilities:
    Build the result payload from the detection output and analyzer results, with fallbacks for the parts that failed, and build the dynamic session payload.

Dependencies:
    The detection result types.

Implementation notes:
    Every builder returns a complete structure with explicit defaults rather than omitting keys, so the frontend can render without defensive checks and a partial scan still produces a renderable document.

Security considerations:
    The payload carries APK-derived strings. JSON encoding makes it safe to transport; escaping is the renderer's responsibility.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from ..detection.results.detection_results import DetectionResult
from ..utils.scoring import (
    calculate_security_score, grade_for, weighted_finding_count)

def _fallback_framework(detection_result: Optional[DetectionResult]) -> Dict[str, Any]:
    """
    Purpose:
        Build the framework section, including the case where detection produced nothing.

    Parameters:
        detection_result: Detection output, possibly None.

    Returns:
        The framework section, always fully formed.

    Implementation notes:
        An absent result yields a section marked as not detected rather than an omitted key, so the dashboard shows "Unknown" rather than a blank panel. The confidence is taken from the top-ranked framework, and several are carried so the UI can show what else was considered.
    """
    fr = getattr(detection_result, "framework_results", None)
    if not fr:
        return {"detected": False, "primary_framework": "Unknown",
                "confidence": 0.0, "confidence_level": "Unknown", "frameworks": []}
    primary = fr.get_primary_framework_name()
    top = fr.get_top_frameworks(10)
    confidence = top[0]["confidence"] if top else 0.0
    level = top[0]["confidence_level"] if top else "Unknown"
    return {
        "detected": primary != "Unknown",
        "primary_framework": primary,
        "confidence": confidence,
        "confidence_level": level,
        "frameworks": top,
    }

def _fallback_app_info(detection_result: Optional[DetectionResult]) -> Dict[str, Any]:
    """
    Purpose:
        Build the application information section from the detection output.

    Parameters:
        detection_result: Detection output, possibly None.

    Returns:
        The application section, empty when no information was extracted.

    Implementation notes:
        Returns an empty mapping rather than placeholder values, leaving the distinction between unknown and absent to the caller that merges this with the richer export.
    """
    info = getattr(detection_result, "basic_info", None)
    if not info:
        return {}
    return {
        "package_name": info.package_name,
        "app_name": info.app_name,
        "version_name": info.version_name,
        "version_code": info.version_code,
        "min_sdk": info.min_sdk,
        "target_sdk": info.target_sdk,
        "file_size": info.file_size,
        "file_size_mb": round(info.get_file_size_mb(), 2),
        "permissions": [],
        "activities": info.activities,
        "services": info.services,
        "receivers": info.receivers,
        "providers": info.providers,
    }

def _analysis_alias(analyzer_results: Dict[str, Any], supported: bool,
                    framework_name: str) -> Dict[str, Any]:
    """
    Purpose:
        Present the analyzer results under the names the dashboard reads.

    Parameters:
        analyzer_results: Raw analyzer output.
        supported: Whether this framework is deeply analysable.
        framework_name: The detected framework.

    Returns:
        The analysis section.

    Implementation notes:
        Success is derived from the decompilation status rather than trusted as a separate flag, so the summary cannot claim success for a scan whose decompilation failed. The alias layer exists so the analyzer output can change its internal key names without breaking the frontend.
    """
    return {
        "supported": supported,
        "success": analyzer_results.get("decompilation_status") == "Successful",
        "files_analyzed": analyzer_results.get("files_analyzed", 0),
        "analysis_time": analyzer_results.get("analysis_time", 0),
        "framework": analyzer_results.get("framework", framework_name),
        "decompilation_status": analyzer_results.get("decompilation_status"),
        "unsupported_framework": analyzer_results.get("unsupported_framework", False),
        "error": analyzer_results.get("error"),
    }


def build_result(
    *,
    json_path: Optional[str],
    detection_result: Optional[DetectionResult],
    analyzer_results: Dict[str, Any],
    supported: bool,
    framework_name: str,
    dynamic_session: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Purpose:
        Assemble the complete scan result for the dashboard and for storage.

    Parameters:
        json_path: Path to the exported JSON, when one was written.
        detection_result: Detection output.
        analyzer_results: Analyzer output.
        supported: Whether the framework is deeply analysable.
        framework_name: The detected framework.
        dynamic_session: Dynamic analysis results, when a session ran.

    Returns:
        The result payload.

    Implementation notes:
        The exported JSON is preferred as the source when it exists, with the fallback builders filling in only what it lacks. That keeps the dashboard and the stored file showing the same thing rather than two separately-assembled views that can disagree. The dynamic session is attached rather than merged, so a reader can tell a runtime observation from a static one.
    """
    data: Dict[str, Any] = {}
    if json_path and Path(json_path).exists():
        try:
            data = json.loads(Path(json_path).read_text(encoding="utf-8"))
        except Exception:
            data = {}

    data.setdefault("framework_detection", _fallback_framework(detection_result))
    data.setdefault("application_info", _fallback_app_info(detection_result))
    data.setdefault(
        "vulnerability_analysis",
        {"analyzed": supported, "total_vulnerabilities": 0,
         "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
         "vulnerabilities": {"critical": [], "high": [], "medium": [], "low": [], "info": []}},
    )
    data.setdefault(
        "summary",
        {"framework_detected": bool(data["framework_detection"].get("detected")),
         "vulnerability_scan_complete": supported,
         "total_vulnerabilities": data["vulnerability_analysis"].get("total_vulnerabilities", 0),
         "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
         "security_score": None},
    )

    data["analysis"] = _analysis_alias(analyzer_results, supported, framework_name)
    from ..config import user_settings

    data["reports"] = {"json": True, "html": True,
                       "pdf": user_settings.get_pdf_generation()}
    data["dynamic_session"] = dynamic_session
    return data

_SEV_BUCKETS = ["critical", "high", "medium", "low", "info"]

def build_dynamic_result(
    *,
    device: Dict[str, Any],
    app_package: str,
    env_checks: Dict[str, Any],
    actions: list,
    runtime_findings: list,
    network_captures: list,
    frida_traces: list,
    reports: Dict[str, Optional[str]],
    detection_result: Optional[DetectionResult] = None,
) -> Dict[str, Any]:
    """
    Purpose:
        Assemble the dynamic session payload.

    Parameters:
        device: The device tested.
        app_package: The package under test.
        env_checks: Outcomes of the environment checks.
        actions: Interactions performed.
        runtime_findings: Findings derived from the session.
        network_captures: Captured traffic summaries.
        frida_traces: Instrumentation output.
        reports: Paths to the reports written for this session, by format.
        detection_result: Detection output for the app, when it could be read from the device.

    Returns:
        The dynamic session payload.

    Implementation notes:
        The environment check outcomes are carried in full, including the failures. A session where interception could not be established produced different evidence from one where it worked, and the report has to say which.

    Security considerations:
        Network captures and instrumentation traces can contain credentials observed at runtime. They are carried here as the session recorded them and are stored with the scan.
    """
    buckets: Dict[str, list] = {sev: [] for sev in _SEV_BUCKETS}
    by_severity = {sev: 0 for sev in _SEV_BUCKETS}
    for finding in runtime_findings or []:
        sev = str(finding.get("severity", "medium")).lower()
        if sev not in buckets:
            sev = "info"
        buckets[sev].append({
            "title": finding.get("vulnerability_type") or finding.get("title") or "Runtime finding",
            "severity": finding.get("severity", sev),
            "description": finding.get("description", ""),
            "file": finding.get("file", "runtime://"),
            "location": finding.get("location") or (str(finding["line_number"]) if finding.get("line_number") else ""),
            "impact": finding.get("impact", ""),
            "code_snippet": finding.get("code_snippet", ""),
            "code_context": finding.get("code_context"),
            "exploitation": finding.get("exploitation", ""),
            "recommendation": finding.get("recommendation", ""),
            "cwe": finding.get("cwe", ""),
            "owasp_mobile": finding.get("owasp_mobile") or finding.get("owasp", ""),
            "vuln_class": finding.get("vuln_class", ""),
            "gate_result": finding.get("gate_result"),
            "chain": finding.get("chain"),
            "chained_into": finding.get("chained_into") or [],
            "related_findings": finding.get("related_findings") or [],
            "source": finding.get("source", ""),
            "surface": finding.get("surface", ""),
        })
        by_severity[sev] += 1

    total = sum(by_severity.values())
    score = calculate_security_score(by_severity)

    framework_detection = _fallback_framework(detection_result)
    application_info = _fallback_app_info(detection_result)
    if not application_info:
        application_info = {
            "package_name": app_package,
            "app_name": app_package,
            "version_name": "",
            "version_code": "",
            "min_sdk": None,
            "target_sdk": None,
            "file_size": 0,
            "file_size_mb": 0,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
    else:
        application_info.setdefault("package_name", app_package)

    return {
        "framework_detection": framework_detection,
        "application_info": application_info,
        "vulnerability_analysis": {
            "analyzed": True,
            "total_vulnerabilities": total,
            "by_severity": by_severity,
            "vulnerabilities": buckets,
        },
        "summary": {
            "framework_detected": bool(framework_detection.get("detected")),
            "vulnerability_scan_complete": True,
            "total_vulnerabilities": total,
            "critical_count": by_severity["critical"],
            "high_count": by_severity["high"],
            "medium_count": by_severity["medium"],
            "low_count": by_severity["low"],
            "security_score": float(score),
            "weighted_finding_count": weighted_finding_count(by_severity),
            "security_grade": grade_for(score),
        },
        "analysis": {
            "supported": True,
            "success": True,
            "files_analyzed": 0,
            "analysis_time": 0,
            "framework": framework_detection.get("primary_framework", "Unknown"),
            "decompilation_status": "Dynamic",
            "unsupported_framework": False,
            "error": None,
        },
        "dynamic_analysis": {
            "device": device,
            "app_package": app_package,
            "env_checks": env_checks,
            "actions": actions or [],
            "network_captures": network_captures or [],
            "frida_traces": frida_traces or [],
            "runtime_findings": runtime_findings or [],
        },
        "reports": {fmt: bool(path) for fmt, path in reports.items()},
        "report_paths": {fmt: (str(path) if path else None) for fmt, path in reports.items()},
    }
