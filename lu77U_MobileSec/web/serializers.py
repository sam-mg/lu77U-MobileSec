"""Build the JSON result the SPA renders from the engine's outputs."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from ..detection.results.detection_results import DetectionResult

def _fallback_framework(detection_result: Optional[DetectionResult]) -> Dict[str, Any]:
    """Minimal framework_detection block when the engine JSON is unavailable."""
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

def build_result(
    *,
    json_path: Optional[str],
    detection_result: Optional[DetectionResult],
    analyzer_results: Dict[str, Any],
    supported: bool,
    framework_name: str,
    dynamic_session: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Merge the engine JSON with analysis metadata + report availability.

    ``dynamic_session`` summarizes Phase 2 (dynamic verification of the static
    findings) for the merged single-scan flow: whether it ran, the device used,
    install/Frida status, and verified/total counts — or, when it didn't run,
    why (setting disabled, no device, install failure, ...). ``None`` when the
    framework isn't supported for deep analysis at all.
    """
    data: Dict[str, Any] = {}
    if json_path and Path(json_path).exists():
        try:
            data = json.loads(Path(json_path).read_text(encoding="utf-8"))
        except Exception:
            data = {}

    # Back-fill the core blocks if the JSON export failed for any reason.
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
         "security_score": 100.0},
    )

    data["analysis"] = {
        "supported": supported,
        "success": analyzer_results.get("decompilation_status") == "Successful",
        "files_analyzed": analyzer_results.get("files_analyzed", 0),
        "analysis_time": analyzer_results.get("analysis_time", 0),
        "framework": analyzer_results.get("framework", framework_name),
        "decompilation_status": analyzer_results.get("decompilation_status"),
        "unsupported_framework": analyzer_results.get("unsupported_framework", False),
        "error": analyzer_results.get("error"),
    }
    # HTML/PDF are generated on demand at export time from this result, so all
    # three formats are always offered (no on-disk paths to track).
    data["reports"] = {"json": True, "html": True, "pdf": True}
    data["dynamic_session"] = dynamic_session
    return data

_SEV_BUCKETS = ["critical", "high", "medium", "low", "info"]
_SEV_WEIGHTS = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}

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
    """Build the SPA-renderable result DTO for a dynamic-analysis scan.

    Keeps the same top-level blocks the static ``build_result`` produces (so the
    Scans list and Scan Detail render unchanged) and folds runtime findings into
    the ``vulnerability_analysis`` severity buckets, then adds a ``dynamic_analysis``
    block with the device/session detail.

    ``detection_result`` is the (best-effort) static detection run against the
    installed APK pulled from the device — when present it drives the real
    ``framework_detection``/``application_info`` blocks via the same
    ``_fallback_framework``/``_fallback_app_info`` helpers the static path uses;
    both already degrade gracefully to "Unknown"/empty when it's ``None``.
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
        })
        by_severity[sev] += 1

    total = sum(by_severity.values())
    score = 100 - sum(by_severity[s] * _SEV_WEIGHTS[s] for s in _SEV_BUCKETS)
    score = max(0, min(100, score))

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