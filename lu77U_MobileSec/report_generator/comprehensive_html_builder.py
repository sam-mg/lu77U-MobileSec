"""Comprehensive HTML Content Builder for Full Analysis Reports"""

import html as _html
import os
import re
from datetime import datetime
from typing import Optional, Dict, List, Any
from lu77U_MobileSec.detection.results import DetectionResult
from ..utils.verbose import verbose_print
from ..config.settings import APP_VERSION
from ..ai.schema import parse_line_span
from .syntax_highlight import highlight_lines, SYNTAX_CSS

def _e(value) -> str:
    """HTML-escape a value; return empty string for None/falsy."""
    return _html.escape(str(value)) if value else ""

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

SEVERITY_DESCRIPTIONS = {
    "critical": "Immediate risk of full device or account compromise",
    "high": "Can expose user data or seriously weaken app security",
    "medium": "Weakens the app's defenses against a motivated attacker",
    "low": "Deviates from recommended secure-coding practices",
    "info": "Worth reviewing; typically not directly exploitable",
}

_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

def _normalize_severity(value) -> str:
    severity = str(value or "info").strip().lower()
    return severity if severity in _SEVERITY_RANK else "info"

class ComprehensiveHTMLBuilder:
    """Builds comprehensive HTML content including vulnerability analysis results"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("ComprehensiveHTMLBuilder initialized", self.verbose)

    def build_comprehensive_report(self, detection_result: DetectionResult, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None) -> str:
        """Build comprehensive HTML content for PDF report including vulnerability analysis"""

        is_unsupported = bool(analyzer_results and analyzer_results.get('unsupported_framework', False))
        vulnerabilities = self._extract_vulnerabilities(vulnerability_results, is_unsupported)

        html = self._build_html_header()
        verbose_print("HTML header built", self.verbose)

        html += self._build_report_header(detection_result, vulnerabilities, is_unsupported, analyzer_results)
        verbose_print("Report header built", self.verbose)

        if is_unsupported:
            html += self._build_unsupported_notice(analyzer_results)
            verbose_print("Unsupported-framework notice built", self.verbose)
        else:
            html += self._build_statistics_section(vulnerabilities)
            verbose_print("Statistics section built", self.verbose)

            html += self._build_vulnerability_index(vulnerabilities)
            verbose_print("Vulnerability index built", self.verbose)

            html += self._build_vulnerability_details(vulnerabilities)
            verbose_print("Vulnerability details built", self.verbose)

        html += self._build_app_info_section(detection_result)
        verbose_print("App info section built", self.verbose)

        html += self._build_analysis_details_section(detection_result, analyzer_results)
        verbose_print("Analysis details section built", self.verbose)

        html += self._build_footer()
        verbose_print("Footer built", self.verbose)

        verbose_print(f"Comprehensive HTML content building complete - total length: {len(html)} characters", self.verbose)
        return html

    def _extract_vulnerabilities(self, vulnerability_results: Optional[Dict], is_unsupported: bool) -> List[Dict]:
        if is_unsupported or not vulnerability_results:
            return []
        vulns = vulnerability_results.get('vulnerabilities')
        return vulns if isinstance(vulns, list) else []

    def _build_html_header(self) -> str:
        """Build HTML document header with enhanced styling"""
        verbose_print("Building comprehensive HTML document header", self.verbose)
        css_preview = self._get_comprehensive_css()[:120]
        css_preview_oneline = css_preview.replace('\n', ' ')
        verbose_print(f"CSS preview (first 120 chars): {css_preview_oneline}", self.verbose)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>lu77U-MobileSec Analysis Report</title>
    <style>
        {self._get_comprehensive_css()}
    </style>
</head>
<body>
    <div class="container">"""

    def _get_comprehensive_css(self) -> str:
        """Get CSS for the comprehensive report — an original, monospace-first
        design (own palette, own typography, own component shapes)."""
        return """
        @page {
            margin: 0.55in;
            size: A4;
            @bottom-center {
                content: "lu77U-MobileSec — Page " counter(page);
                font-family: "Menlo", "SF Mono", Monaco, "DejaVu Sans Mono", monospace;
                font-size: 7.5pt;
                color: #9099A8;
            }
        }

        * { box-sizing: border-box; }

        body {
            font-family: "Menlo", "SF Mono", Monaco, "DejaVu Sans Mono", monospace;
            font-size: 9pt;
            line-height: 1.55;
            color: #1F2430;
        }

        .container { max-width: 100%; }

        /* --- Report header / cover --- */
        .report-header {
            padding-bottom: 18px;
            margin-bottom: 20px;
            border-bottom: 1px solid #E7E9EE;
        }
        .brand {
            font-size: 12.5pt;
            font-weight: bold;
            letter-spacing: 0.5px;
            color: #1F2430;
            margin: 0 0 16px 0;
        }
        .severity-chips { margin-bottom: 16px; }
        .chip {
            display: inline-block;
            vertical-align: middle;
            padding: 4px 10px 4px 8px;
            border: 1px solid #E7E9EE;
            border-radius: 12px;
            background: #FAFBFC;
            font-size: 8pt;
            margin: 0 8px 6px 0;
        }
        .chip .chip-count { font-weight: bold; }
        .tagline {
            font-size: 9pt;
            color: #6A7280;
            max-width: 85%;
            margin: 0 0 18px 0;
        }
        .app-title {
            font-size: 19pt;
            font-weight: bold;
            color: #1F2430;
            margin: 0 0 6px 0;
            word-break: break-word;
        }
        .app-id-line { font-size: 9pt; color: #6A7280; margin: 0; }
        .app-id-line strong { color: #1F2430; }
        .app-id-line .sep { margin: 0 10px; color: #C7CBD3; }

        /* --- Generic section --- */
        .section { margin-bottom: 24px; page-break-inside: avoid; }
        .section h2 {
            font-size: 11.5pt;
            font-weight: bold;
            color: #1F2430;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #E7E9EE;
            padding-bottom: 6px;
            margin: 0 0 14px 0;
        }
        .section h3 {
            font-size: 10pt;
            font-weight: bold;
            color: #1F2430;
            margin: 16px 0 8px 0;
        }

        .status-note {
            font-size: 9pt;
            color: #6A7280;
            text-align: center;
            padding: 24px 0;
        }

        /* --- Notice / callout card (unsupported framework, no findings) --- */
        .notice-card {
            background: #FAFBFC;
            border: 1px solid #E7E9EE;
            border-left: 3px solid #5B7C99;
            border-radius: 8px;
            padding: 14px 16px;
        }
        .notice-card h3 { margin-top: 0; }
        .notice-card p { margin: 6px 0; font-size: 9pt; color: #3A404A; }

        /* --- Info grid (key/value table) --- */
        .info-grid {
            display: table;
            width: 100%;
            border: 1px solid #E7E9EE;
            border-radius: 8px;
            background: #FAFBFC;
            margin-bottom: 14px;
        }
        .info-row { display: table-row; }
        .info-row .info-label, .info-row .info-value {
            border-bottom: 1px solid #E7E9EE;
        }
        .info-row:last-child .info-label, .info-row:last-child .info-value {
            border-bottom: none;
        }
        .info-label {
            display: table-cell;
            font-weight: bold;
            padding: 7px 12px;
            width: 32%;
            color: #1F2430;
            font-size: 8.5pt;
            vertical-align: top;
        }
        .info-value {
            display: table-cell;
            padding: 7px 12px;
            color: #3A404A;
            font-size: 8.5pt;
            vertical-align: top;
            word-break: break-word;
        }

        /* --- Component lists (activities / services / ...) --- */
        .component-block { margin-top: 12px; }
        .component-block h4 {
            font-size: 8.5pt;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: #6A7280;
            margin: 0 0 6px 0;
        }
        .component-list {
            background: #FAFBFC;
            border: 1px solid #E7E9EE;
            border-radius: 8px;
            padding: 10px 14px 10px 26px;
            margin-bottom: 10px;
        }
        .component-list li { font-size: 8pt; margin: 2px 0; word-break: break-all; }

        /* --- Framework badges --- */
        .framework-badges { margin-top: 8px; }
        .framework-badge {
            display: inline-block;
            padding: 4px 10px;
            border: 1px solid #E7E9EE;
            border-radius: 12px;
            background: #FAFBFC;
            font-size: 8pt;
            margin: 0 8px 6px 0;
        }
        .framework-badge .confidence { color: #6A7280; }

        /* --- Severity dot --- */
        .dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            border: 2px solid;
            vertical-align: middle;
            margin-right: 6px;
        }
        .dot.critical { background: #F9E6E4; border-color: #B3261E; }
        .dot.high     { background: #FBE9E4; border-color: #E0654F; }
        .dot.medium   { background: #FBF3DC; border-color: #D99A06; }
        .dot.low      { background: #E3F3EC; border-color: #3D9A6E; }
        .dot.info     { background: #EAF0F5; border-color: #5B7C99; }

        .sev-text.critical { color: #B3261E; }
        .sev-text.high     { color: #E0654F; }
        .sev-text.medium   { color: #D99A06; }
        .sev-text.low      { color: #3D9A6E; }
        .sev-text.info     { color: #5B7C99; }

        /* --- Statistics cards --- */
        .stat-total { font-size: 10pt; margin: 0 0 14px 0; }
        .stat-total strong { font-size: 14pt; }
        .stat-cards {
            display: flex;
            gap: 12px;
            margin-bottom: 6px;
        }
        .stat-card {
            flex: 1;
            background: #FAFBFC;
            border: 1px solid #E7E9EE;
            border-radius: 10px;
            padding: 12px;
        }
        .stat-card-label {
            font-weight: bold;
            font-size: 8.5pt;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            margin-bottom: 6px;
        }
        .stat-card-desc {
            font-size: 7.3pt;
            color: #6A7280;
            line-height: 1.4;
            margin-bottom: 10px;
            min-height: 26px;
        }
        .stat-card-pct { font-size: 15pt; font-weight: bold; margin-bottom: 8px; }
        .stat-bar-track { background: #E7E9EE; border-radius: 4px; height: 5px; overflow: hidden; }
        .stat-bar-fill { height: 100%; border-radius: 4px; }
        .security-score { margin-top: 12px; font-size: 9pt; color: #3A404A; }
        .security-score strong { font-size: 10.5pt; }

        /* --- Vulnerability index table --- */
        .index-table-wrap {
            border: 1px solid #E7E9EE;
            border-radius: 10px;
            overflow: hidden;
        }
        .index-table { width: 100%; border-collapse: collapse; font-size: 8.3pt; }
        .index-table th {
            text-align: left;
            background: #FAFBFC;
            padding: 8px 12px;
            border-bottom: 1px solid #E7E9EE;
            font-size: 7.3pt;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: #6A7280;
        }
        .index-table td {
            padding: 8px 12px;
            border-bottom: 1px solid #E7E9EE;
            vertical-align: middle;
        }
        .index-table tr:last-child td { border-bottom: none; }
        .index-table td.num, .index-table th.num { width: 30px; color: #6A7280; }
        .index-table td.amount, .index-table th.amount { width: 70px; text-align: right; }

        /* --- Vulnerability detail items --- */
        .vuln-item {
            margin-bottom: 20px;
            padding-left: 16px;
            border-left: 3px solid #E7E9EE;
            page-break-inside: avoid;
        }
        .vuln-item.critical { border-left-color: #B3261E; }
        .vuln-item.high     { border-left-color: #E0654F; }
        .vuln-item.medium   { border-left-color: #D99A06; }
        .vuln-item.low      { border-left-color: #3D9A6E; }
        .vuln-item.info     { border-left-color: #5B7C99; }

        .vuln-item-head { margin-bottom: 8px; }
        .vuln-item-title { font-size: 10.5pt; font-weight: bold; color: #1F2430; vertical-align: middle; }

        .found-in { font-size: 8.3pt; color: #6A7280; margin: 4px 0 10px 0; }
        .found-in code {
            background: #F5F6F8;
            border: 1px solid #E7E9EE;
            padding: 1px 5px;
            border-radius: 3px;
            font-size: 8pt;
        }

        .vuln-item h4 {
            font-size: 8pt;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: #6A7280;
            margin: 14px 0 5px 0;
        }
        .vuln-item p { font-size: 8.8pt; line-height: 1.55; margin: 0 0 4px 0; color: #2B303B; }

        .code-block {
            border: 1px solid #E7E9EE;
            border-radius: 8px;
            overflow: hidden;
            margin: 6px 0 6px 0;
            background: #F5F6F8;
        }
        .code-table { width: 100%; border-collapse: collapse; font-size: 7.8pt; }
        .code-table td.ln {
            width: 1%;
            white-space: nowrap;
            padding: 1px 10px;
            text-align: right;
            color: #9099A8;
            border-right: 1px solid #E7E9EE;
        }
        .code-table td.code {
            padding: 1px 12px;
            white-space: pre-wrap;
            word-break: break-word;
            color: #1F2430;
        }
        .code-table tr.hl td { background: #FBE9E4; }
        .code-table tr.hl td.ln { color: #B3261E; font-weight: bold; }

        .callout {
            padding: 10px 12px;
            border-radius: 6px;
            margin: 4px 0 4px 0;
            font-size: 8.5pt;
            line-height: 1.5;
        }
        .callout .callout-label {
            display: block;
            text-transform: uppercase;
            font-size: 7.3pt;
            letter-spacing: 0.4px;
            font-weight: bold;
            margin-bottom: 4px;
        }
        .callout.impact { background: #F9E6E4; color: #7A241D; }
        .callout.impact .callout-label { color: #B3261E; }
        .callout.exploitation { background: #FBF3DC; color: #6B5205; }
        .callout.exploitation .callout-label { color: #D99A06; }
        .callout.dyn-verified { background: #E3F3EC; color: #1F5C42; }
        .callout.dyn-verified .callout-label { color: #3D9A6E; }
        .callout.dyn-unverified { background: #F1F2F5; color: #4A5160; }
        .callout.dyn-unverified .callout-label { color: #6A7280; }

        .dyn-pill {
            display: inline-block;
            font-size: 7.3pt;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            padding: 2px 7px;
            border-radius: 10px;
            margin-left: 8px;
            vertical-align: middle;
        }
        .dyn-pill.verified { background: #E3F3EC; color: #1F5C42; border: 1px solid #3D9A6E; }
        .dyn-pill.unverified { background: #FBE9E4; color: #7A241D; border: 1px solid #E0654F; text-decoration: line-through; }
        .dyn-pill.notattempted { background: #F1F2F5; color: #4A5160; border: 1px solid #C7CCD4; }

        .cvss-pill {
            display: inline-block;
            font-size: 7.3pt;
            font-weight: bold;
            letter-spacing: 0.2px;
            padding: 2px 7px;
            border-radius: 10px;
            margin-left: 8px;
            vertical-align: middle;
            background: #F1F2F5;
            color: #3A404A;
            border: 1px solid #C7CCD4;
        }
        .cvss-vector {
            font-size: 7.6pt;
            color: #8992A0;
            font-family: 'SFMono-Regular', Consolas, monospace;
            margin: 2px 0 4px 0;
        }

        .references { margin: 4px 0 0 0; padding-left: 16px; }
        .references li { font-size: 8.3pt; color: #3A404A; margin: 2px 0; }
        .references a { color: #5B7C99; text-decoration: none; word-break: break-all; }

        /* --- Footer --- */
        .report-footer {
            margin-top: 30px;
            padding-top: 14px;
            border-top: 1px solid #E7E9EE;
            text-align: center;
            font-size: 7.5pt;
            color: #6A7280;
        }
        .report-footer p { margin: 3px 0; }
        .report-footer a { color: #5B7C99; text-decoration: none; }

        @media print {
            .section, .vuln-item, .stat-cards, .notice-card { page-break-inside: avoid; }
        }
        """ + SYNTAX_CSS

    def _build_report_header(self, detection_result: DetectionResult, vulnerabilities: List[Dict], is_unsupported: bool, analyzer_results: Optional[Dict]) -> str:
        verbose_print("Building report header", self.verbose)

        counts = self._count_by_severity(vulnerabilities)

        chips_html = ""
        if not is_unsupported:
            for severity in SEVERITY_ORDER:
                chips_html += (
                    f'<span class="chip"><span class="dot {severity}"></span>'
                    f'<span class="chip-count">{counts[severity]}</span> {SEVERITY_LABELS[severity]}</span>'
                )

        app_name = "Unknown application"
        package_name = "Unknown"
        version_name = "Unknown"

        if detection_result.basic_info:
            app_name = getattr(detection_result.basic_info, 'app_name', None) or self._target_basename(detection_result.target_path)
            package_name = getattr(detection_result.basic_info, 'package_name', None) or "Unknown"
            version_name = getattr(detection_result.basic_info, 'version_name', None) or "Unknown"
        else:
            app_name = self._target_basename(detection_result.target_path)

        return f"""
        <div class="report-header">
            <p class="brand">lu77U-MobileSec</p>
            <div class="severity-chips">{chips_html}</div>
            <p class="tagline">Static application security analysis for Android &amp; iOS apps —
                surfacing insecure code paths, unsafe configuration, and hardening gaps
                before they reach production.</p>
            <h1 class="app-title">{_e(app_name)}</h1>
            <p class="app-id-line">App ID <strong>{_e(package_name)}</strong><span class="sep">|</span>Version <strong>{_e(version_name)}</strong></p>
        </div>"""

    def _target_basename(self, target_path: Optional[str]) -> str:
        if not target_path:
            return "Unknown application"
        return os.path.basename(target_path.rstrip('/')) or target_path

    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for vuln in vulnerabilities:
            counts[_normalize_severity(vuln.get('severity'))] += 1
        return counts

    def _build_unsupported_notice(self, analyzer_results: Dict) -> str:
        framework_name = analyzer_results.get('framework', 'this framework')
        return f"""
        <div class="section">
            <h2>Vulnerability Analysis</h2>
            <div class="notice-card">
                <h3>Framework analysis not yet available</h3>
                <p>The framework <strong>{_e(framework_name)}</strong> was successfully detected.</p>
                <p>Vulnerability analysis for this framework is currently under development
                    and will be available in a future release.</p>
            </div>
        </div>"""

    def _build_statistics_section(self, vulnerabilities: List[Dict]) -> str:
        verbose_print("Building statistics section", self.verbose)

        total = len(vulnerabilities)
        counts = self._count_by_severity(vulnerabilities)

        security_score = max(0, 100 - (counts['critical'] * 25) - (counts['high'] * 10) - (counts['medium'] * 5) - (counts['low'] * 2))

        if total == 0:
            return f"""
        <div class="section">
            <h2>Statistics</h2>
            <p class="status-note">No security vulnerabilities were detected in this analysis.</p>
            <p class="security-score">Security score: <strong>{security_score:.1f}</strong> / 100</p>
        </div>"""

        cards_html = ""
        for severity in SEVERITY_ORDER:
            count = counts[severity]
            pct = (count / total * 100) if total else 0
            cards_html += f"""
                <div class="stat-card">
                    <div class="stat-card-label sev-text {severity}">{SEVERITY_LABELS[severity]}</div>
                    <div class="stat-card-desc">{_e(SEVERITY_DESCRIPTIONS[severity])}</div>
                    <div class="stat-card-pct sev-text {severity}">{pct:.0f}%</div>
                    <div class="stat-bar-track"><div class="stat-bar-fill dot {severity}" style="width:{pct:.0f}%; background:currentColor;"></div></div>
                </div>"""

        return f"""
        <div class="section">
            <h2>Statistics</h2>
            <p class="stat-total"><strong>{total}</strong> vulnerabilit{'y' if total == 1 else 'ies'} found</p>
            <div class="stat-cards">{cards_html}
            </div>
            <p class="security-score">Security score: <strong>{security_score:.1f}</strong> / 100</p>
        </div>"""

    def _group_vulnerabilities_by_title(self, vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        for vuln in vulnerabilities:
            title = vuln.get('title') or vuln.get('vulnerability_type') or 'Security Issue'
            severity = _normalize_severity(vuln.get('severity'))
            group = groups.setdefault(title, {'title': title, 'severity': severity, 'count': 0})
            group['count'] += 1
            if _SEVERITY_RANK[severity] < _SEVERITY_RANK[group['severity']]:
                group['severity'] = severity

        rows = list(groups.values())
        rows.sort(key=lambda r: (_SEVERITY_RANK[r['severity']], -r['count'], r['title'].lower()))
        return rows

    def _build_vulnerability_index(self, vulnerabilities: List[Dict]) -> str:
        verbose_print("Building vulnerability index", self.verbose)

        if not vulnerabilities:
            return """
        <div class="section">
            <h2>List of Vulnerabilities</h2>
            <p class="status-note">No security vulnerabilities detected.</p>
        </div>"""

        rows = self._group_vulnerabilities_by_title(vulnerabilities)

        rows_html = ""
        for i, row in enumerate(rows, 1):
            severity = row['severity']
            rows_html += f"""
                    <tr>
                        <td class="num">{i}</td>
                        <td>{_e(row['title'])}</td>
                        <td><span class="dot {severity}"></span><span class="sev-text {severity}">{SEVERITY_LABELS[severity]}</span></td>
                        <td class="amount">{row['count']}</td>
                    </tr>"""

        return f"""
        <div class="section">
            <h2>List of Vulnerabilities</h2>
            <div class="index-table-wrap">
                <table class="index-table">
                    <thead>
                        <tr>
                            <th class="num">#</th>
                            <th>Category</th>
                            <th>Level</th>
                            <th class="amount">Amount</th>
                        </tr>
                    </thead>
                    <tbody>{rows_html}
                    </tbody>
                </table>
            </div>
        </div>"""

    def _sorted_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        def key(vuln: Dict):
            severity = _normalize_severity(vuln.get('severity'))
            title = vuln.get('title') or vuln.get('vulnerability_type') or ''
            return (_SEVERITY_RANK[severity], title.lower())
        return sorted(vulnerabilities, key=key)

    def _build_vulnerability_details(self, vulnerabilities: List[Dict]) -> str:
        verbose_print("Building vulnerability details", self.verbose)

        if not vulnerabilities:
            return ""

        items_html = "".join(self._format_vulnerability_item(v) for v in self._sorted_vulnerabilities(vulnerabilities))

        return f"""
        <div class="section">
            <h2>Vulnerabilities in the Code</h2>
            {items_html}
        </div>"""

    def _render_code_table(self, lines: List[str], first_line: int, highlight_start: Optional[int],
                             highlight_end: Optional[int], filename: str,
                             lines_html: Optional[List[str]] = None) -> str:
        """Render a gutter + syntax-highlighted code table. ``highlight_start``/
        ``highlight_end`` (inclusive, 1-based) mark the vulnerable span; pass
        both ``None`` to highlight nothing. ``lines_html`` reuses HTML already
        colorized by the analyzer (avoids re-running Pygments); computed here
        when absent."""
        if not lines:
            return ""

        highlighted = lines_html if lines_html and len(lines_html) == len(lines) else highlight_lines(lines, filename)
        rows_html = ""
        for offset, code_html in enumerate(highlighted):
            line_no = first_line + offset
            is_hl = highlight_start is not None and highlight_end is not None and highlight_start <= line_no <= highlight_end
            row_class = ' class="hl"' if is_hl else ''
            rows_html += f'<tr{row_class}><td class="ln">{line_no}</td><td class="code">{code_html or "&nbsp;"}</td></tr>'

        return f"""<div class="code-block"><table class="code-table"><tbody>{rows_html}</tbody></table></div>"""

    def _format_code_block(self, vuln: Dict) -> str:
        """Render the code block for a finding: real ±context source lines
        when the analyzer resolved them (``code_context``, syntax-highlighted
        HTML precomputed), else the AI's own ``code_snippet`` with a
        best-effort highlight parsed from ``location`` (single line or range)."""
        filename = vuln.get('file', '')
        context = vuln.get('code_context')

        if isinstance(context, dict) and context.get('lines'):
            return self._render_code_table(
                lines=context['lines'],
                first_line=context.get('start_line', 1),
                highlight_start=context.get('highlight_start'),
                highlight_end=context.get('highlight_end'),
                filename=filename,
                lines_html=context.get('lines_html'),
            )

        code_snippet = vuln.get('code_snippet', vuln.get('code', ''))
        if not code_snippet:
            return ""

        lines = code_snippet.splitlines() or ['']
        span = parse_line_span(vuln.get('line') or vuln.get('location', ''))
        highlight_start, highlight_end = span if span else (None, None)
        first_line = highlight_start or 1
        return self._render_code_table(
            lines=lines,
            first_line=first_line,
            highlight_start=highlight_start,
            highlight_end=highlight_end,
            filename=filename,
        )

    def _cwe_link(self, cwe: Optional[str]) -> Optional[str]:
        if not cwe:
            return None
        match = re.search(r'(\d+)', cwe)
        if not match:
            return None
        return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"

    def _format_vulnerability_item(self, vuln: Dict) -> str:
        """Format a single vulnerability finding with code context."""
        title = _e(vuln.get('title', vuln.get('vulnerability_type', 'Security Issue')))
        description = _e(vuln.get('description', 'No description available'))
        severity = _normalize_severity(vuln.get('severity'))
        file_path = _e(vuln.get('file', 'Unknown file'))
        recommendation = _e(vuln.get('recommendation', ''))
        cwe = vuln.get('cwe', '')
        impact = _e(vuln.get('impact', ''))
        exploitation = _e(vuln.get('exploitation', ''))
        owasp_mobile = _e(vuln.get('owasp_mobile', ''))

        cvss_score = vuln.get('cvss_score')
        cvss_vector = vuln.get('cvss_vector')
        cvss_pill_html = (
            f'<span class="cvss-pill">CVSS {cvss_score:.1f}</span>' if cvss_score is not None else ''
        )
        cvss_vector_html = (
            f'<div class="cvss-vector">{_e(cvss_vector)}</div>' if cvss_vector else ''
        )

        found_in = f'<p class="found-in">Found in the file <code>{file_path}</code></p>' if file_path else ''
        code_block = self._format_code_block(vuln)

        dyn_pill_html, dyn_callout_html = self._format_dynamic_verification(vuln)

        impact_html = (
            f'<div class="callout impact"><span class="callout-label">Impact</span>{impact}</div>'
            if impact else ''
        )
        exploitation_html = (
            f'<div class="callout exploitation"><span class="callout-label">Exploitation</span>{exploitation}</div>'
            if exploitation else ''
        )
        recommendation_html = (
            f'<h4>Remediation</h4><p>{recommendation}</p>' if recommendation else ''
        )

        cwe_link = self._cwe_link(cwe)
        references_items = ""
        if cwe_link:
            references_items += f'<li>CWE: <a href="{cwe_link}">{_e(cwe)}</a></li>'
        if owasp_mobile:
            references_items += f'<li>OWASP Mobile: {owasp_mobile}</li>'
        references_html = (
            f'<h4>References</h4><ul class="references">{references_items}</ul>' if references_items else ''
        )

        return f"""
            <div class="vuln-item {severity}">
                <div class="vuln-item-head">
                    <span class="dot {severity}"></span><span class="vuln-item-title">{title}</span>{cvss_pill_html}{dyn_pill_html}
                </div>
                {cvss_vector_html}
                {found_in}
                {code_block}
                <h4>Vulnerability Description</h4>
                <p>{description}</p>
                {impact_html}
                {exploitation_html}
                {dyn_callout_html}
                {recommendation_html}
                {references_html}
            </div>"""

    def _format_dynamic_verification(self, vuln: Dict) -> "tuple[str, str]":
        """Return ``(pill_html, callout_html)`` for a finding's dynamic-
        verification status: a small pill next to the title (green
        "Verified" / red struck-through "Dynamic" / grey "Not Run"), and a
        callout spelling out the evidence or the specific reason it wasn't
        proven at runtime. Both are empty strings when the finding carries no
        ``dynamic_verification`` (e.g. reports generated before this field
        existed)."""
        dv = vuln.get('dynamic_verification')
        if not isinstance(dv, dict) or not dv.get('status'):
            return '', ''

        status = dv.get('status')
        if status == 'verified':
            pill = '<span class="dyn-pill verified">Dynamic Verified</span>'
            evidence = _e(dv.get('evidence', ''))
            callout = (
                f'<div class="callout dyn-verified">'
                f'<span class="callout-label">Dynamic Verification — Verified</span>{evidence}</div>'
                if evidence else ''
            )
            return pill, callout

        label = 'Dynamic — Not Run' if status == 'not_attempted' else 'Dynamic — Unverified'
        pill_cls = 'notattempted' if status == 'not_attempted' else 'unverified'
        pill = f'<span class="dyn-pill {pill_cls}">{label}</span>'
        reason = _e(dv.get('reason', ''))
        heading = "Why dynamic verification didn't run" if status == 'not_attempted' \
            else 'Why dynamic verification could not confirm this'
        callout = (
            f'<div class="callout dyn-unverified">'
            f'<span class="callout-label">{heading}</span>{reason}</div>'
            if reason else ''
        )
        return pill, callout

    def _build_app_info_section(self, detection_result: DetectionResult) -> str:
        """Build application information section"""
        html = """
        <div class="section">
            <h2>Application Information</h2>"""

        if detection_result.basic_info:
            html += self._build_basic_info_grid(detection_result)
            html += self._build_components_section(detection_result)
        else:
            html += '<p class="status-note">No application information available</p>'

        html += "</div>"
        return html

    def _build_basic_info_grid(self, detection_result: DetectionResult) -> str:
        """Build basic app information grid"""
        basic_info = detection_result.basic_info

        rows = []
        if getattr(basic_info, 'app_name', None):
            rows.append(("Application Name", basic_info.app_name))
        if getattr(basic_info, 'package_name', None):
            rows.append(("Package Name", basic_info.package_name))
        if getattr(basic_info, 'version_name', None):
            rows.append(("Version Name", basic_info.version_name))
        if getattr(basic_info, 'version_code', None):
            rows.append(("Version Code", basic_info.version_code))
        if getattr(basic_info, 'file_size', None):
            rows.append(("File Size", basic_info.get_file_size_formatted()))
        if getattr(basic_info, 'file_type', None):
            rows.append(("File Type", basic_info.file_type))
        if getattr(basic_info, 'min_sdk', None):
            rows.append(("Minimum SDK", basic_info.min_sdk))
        if getattr(basic_info, 'target_sdk', None):
            rows.append(("Target SDK", basic_info.target_sdk))

        if not rows:
            return ""

        rows_html = "".join(
            f'<div class="info-row"><div class="info-label">{_e(label)}</div>'
            f'<div class="info-value">{_e(value)}</div></div>'
            for label, value in rows
        )
        return f'<div class="info-grid">{rows_html}</div>'

    def _build_components_section(self, detection_result: DetectionResult) -> str:
        """Build application components section"""
        basic_info = detection_result.basic_info

        groups = [
            ("Activities", getattr(basic_info, 'activities', None)),
            ("Services", getattr(basic_info, 'services', None)),
            ("Broadcast Receivers", getattr(basic_info, 'receivers', None)),
            ("Content Providers", getattr(basic_info, 'providers', None)),
        ]

        total_components = sum(len(items) for _, items in groups if items)
        if total_components == 0:
            return ""

        html = f'<div class="component-block"><h3>Android Components ({total_components} total)</h3>'
        for label, items in groups:
            if not items:
                continue
            list_items = "".join(f'<li>{_e(item)}</li>' for item in items)
            html += f"""
                <h4>{_e(label)} ({len(items)})</h4>
                <div class="component-list"><ul>{list_items}</ul></div>"""
        html += '</div>'
        return html

    def _dedupe_frameworks(self, detection_result: DetectionResult) -> List[Dict[str, Any]]:
        if not detection_result.framework_results or not detection_result.framework_results.detected_frameworks:
            return []

        by_name: Dict[str, Dict[str, Any]] = {}
        for framework in detection_result.framework_results.detected_frameworks:
            if isinstance(framework, dict):
                name = framework.get('framework', 'Unknown')
                confidence = framework.get('confidence', 0)
            else:
                name = str(framework)
                confidence = 0
            if name not in by_name or confidence > by_name[name]['confidence']:
                by_name[name] = {'framework': name, 'confidence': confidence}

        return sorted(by_name.values(), key=lambda x: x['confidence'], reverse=True)

    def _build_analysis_details_section(self, detection_result: DetectionResult, analyzer_results: Optional[Dict]) -> str:
        """Merged framework detection + analyzer info card."""
        verbose_print("Building analysis details section", self.verbose)

        frameworks = self._dedupe_frameworks(detection_result)
        primary = detection_result.framework_results.get_primary_framework_name() if detection_result.framework_results else "Unknown"

        rows = []
        if detection_result.framework_results:
            rows.append(("Primary Framework", primary))
            rows.append(("Frameworks Detected", len(frameworks)))
        if analyzer_results:
            if 'analysis_time' in analyzer_results:
                rows.append(("Analysis Time", f"{analyzer_results['analysis_time']:.2f}s"))
            if 'files_analyzed' in analyzer_results:
                rows.append(("Files Analyzed", analyzer_results['files_analyzed']))

        if not rows and not frameworks:
            return ""

        rows_html = "".join(
            f'<div class="info-row"><div class="info-label">{_e(label)}</div>'
            f'<div class="info-value">{_e(value)}</div></div>'
            for label, value in rows
        )

        badges_html = ""
        if frameworks:
            badges = "".join(
                f'<span class="framework-badge">{_e(fw["framework"])}'
                + (f' <span class="confidence">{fw["confidence"]:.0%}</span>' if fw['confidence'] > 0 else '')
                + '</span>'
                for fw in frameworks
            )
            badges_html = f'<div class="framework-badges">{badges}</div>'

        return f"""
        <div class="section">
            <h2>Analysis Details</h2>
            <div class="info-grid">{rows_html}</div>
            {badges_html}
        </div>"""

    def _build_footer(self) -> str:
        """Build report footer"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""
        <div class="report-footer">
            <p>Generated by lu77U-MobileSec v{APP_VERSION} &bull; {timestamp}</p>
            <p><a href="https://github.com/sam-mg/lu77U-MobileSec">https://github.com/sam-mg/lu77U-MobileSec</a></p>
        </div>
    </div>
</body>
</html>"""