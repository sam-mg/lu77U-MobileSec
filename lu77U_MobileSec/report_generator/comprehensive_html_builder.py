#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.comprehensive_html_builder

Purpose:
    Build the full security report: the findings with their evidence, the gate verdicts that shaped them, the chains they form, what the analysis did and did not cover, and the app's identity.

Responsibilities:
    Assemble every section, render code excerpts with highlighting, and escape everything that came from the APK.

Dependencies:
    The syntax highlighter, the line-span parser.

Implementation notes:
    This is the report a reader actually acts on, so it is built to be defensible rather than merely informative: each finding carries its evidence, its verdict and the reason behind that verdict, and the coverage notices state plainly where the analysis was incomplete. The same document is rendered to HTML and to PDF, which is why nothing here references a remote resource.

Security considerations:
    Every APK-derived value goes through the escape helper before it reaches the document. This matters more here than anywhere else in the tool: a finding's title, file path and code excerpt are all attacker-influenced, and this report is opened in a browser. Any new interpolation added here must be escaped the same way.
"""

import html as _html
import os
import re
from datetime import datetime
from typing import Optional, Dict, List, Any
from lu77U_MobileSec.detection.results import DetectionResult
from ..utils.verbose import verbose_print
from ..utils.cvss import severity_from_score
from ..utils.scoring import calculate_security_score
from ..config.settings import APP_NAME, APP_VERSION
from ..config.branding import FAVICON_LINK_TAG
from .._metadata import HOMEPAGE
from ..ai.schema import parse_line_span
from .syntax_highlight import highlight_lines, SYNTAX_CSS

def _e(value) -> str:
    """
    Purpose:
        Escape a value for safe inclusion in the report.

    Parameters:
        value: Any value; coerced to string.

    Returns:
        The HTML-escaped text, or an empty string for a falsy value.

    Security considerations:
        This is the single escaping point for the report. Values reaching it come from an untrusted APK -- app labels, class names, code excerpts, model-written descriptions -- and the report is rendered by a browser. Interpolating any such value without it would be stored cross-site scripting in a document the analyst opens.

    Implementation notes:
        Falsy values become an empty string rather than the text "None" or "0", so an absent field renders as blank. Note that a genuine zero also renders blank, which is acceptable because no numeric field is passed through here.
    """
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
    """
    Purpose:
        Map a severity onto the report's fixed ladder.

    Parameters:
        value: Severity text, or None.

    Returns:
        One of the five known severity keys.

    Implementation notes:
        An unrecognised severity becomes informational rather than raising, because this runs during rendering and an unexpected value must not lose the whole report. The validation upstream is what keeps that case from arising.
    """
    severity = str(value or "info").strip().lower()
    return severity if severity in _SEVERITY_RANK else "info"

class ComprehensiveHTMLBuilder:
    """
    Purpose:
        Builds the full security report as a single HTML document.

    Attributes:
        verbose: Whether building is traced.

    Invariants:
        The document is self-contained: styles are inlined and no remote resource is referenced, so it renders identically offline and through the PDF engine.

    Thread-safety:
        Holds no per-report state.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Construct the builder.

        Parameters:
            verbose: Enables tracing.
        """
        self.verbose = verbose
        verbose_print("ComprehensiveHTMLBuilder initialized", self.verbose)

    def build_comprehensive_report(self, detection_result: DetectionResult, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None) -> str:
        """
        Purpose:
            Assemble the complete report document.

        Parameters:
            detection_result: Detection output.
            vulnerability_results: Findings from the analysis.
            analyzer_results: Per-analyzer detail, including coverage.

        Returns:
            The report HTML.

        Implementation notes:
            Sections are ordered for a reader working top to bottom: the header and its score, then any coverage caveats, then the statistics, the index, and finally the findings in full. The caveats come before the numbers deliberately -- a reader should know the analysis was incomplete before they read a count. A failed analysis gets its own notice in place of the statistics, which would otherwise announce that nothing was found and a score of 100 for an app nobody read.
        """
        is_unsupported = bool(analyzer_results and analyzer_results.get('unsupported_framework', False))
        all_vulnerabilities = self._extract_vulnerabilities(vulnerability_results, is_unsupported)
        vulnerabilities = [v for v in all_vulnerabilities
                           if not (v.get('gate_result') or {}).get('mechanically_refuted')]
        refuted_vulnerabilities = [v for v in all_vulnerabilities
                                   if (v.get('gate_result') or {}).get('mechanically_refuted')]

        html = self._build_html_header()
        verbose_print("HTML header built", self.verbose)

        html += self._build_report_header(detection_result, vulnerabilities, is_unsupported)
        verbose_print("Report header built", self.verbose)

        html += self._build_coverage_notice(analyzer_results)
        html += self._build_scope_notice(analyzer_results)
        html += self._build_limitation_notice(analyzer_results)

        analysis_failed = bool(analyzer_results) and not is_unsupported and (
            analyzer_results.get('decompilation_status') == 'Failed')
        if is_unsupported:
            html += self._build_unsupported_notice(analyzer_results)
            verbose_print("Unsupported-framework notice built", self.verbose)
        elif analysis_failed:
            html += self._build_failed_notice(analyzer_results)
            verbose_print("Failed-analysis notice built", self.verbose)
        else:
            html += self._build_statistics_section(vulnerabilities)
            verbose_print("Statistics section built", self.verbose)

            html += self._build_vulnerability_index(vulnerabilities)
            verbose_print("Vulnerability index built", self.verbose)

            html += self._build_vulnerability_details(vulnerabilities)
            verbose_print("Vulnerability details built", self.verbose)

            html += self._build_refuted_section(refuted_vulnerabilities)
            verbose_print("Refuted section built", self.verbose)

        html += self._build_app_info_section(detection_result)
        verbose_print("App info section built", self.verbose)

        html += self._build_analysis_details_section(detection_result, analyzer_results)
        verbose_print("Analysis details section built", self.verbose)

        html += self._build_footer()
        verbose_print("Footer built", self.verbose)

        verbose_print(f"Comprehensive HTML content building complete - total length: {len(html)} characters", self.verbose)
        return html

    def _extract_vulnerabilities(self, vulnerability_results: Optional[Dict], is_unsupported: bool) -> List[Dict]:
        """
        Purpose:
            Pull the finding list out of the results, whichever shape it arrived in.

        Parameters:
            vulnerability_results: Findings from the analysis.
            is_unsupported: Whether the framework was one this tool cannot analyse deeply.

        Returns:
            The findings.

        Implementation notes:
            An unsupported framework yields no findings rather than an empty analysis presented as a clean result; the accompanying notice explains why.
        """
        if is_unsupported or not vulnerability_results:
            return []
        vulns = vulnerability_results.get('vulnerabilities')
        return vulns if isinstance(vulns, list) else []

    def _build_html_header(self) -> str:
        """
        Purpose:
            Build the document head, including the inlined stylesheet.

        Returns:
            The opening HTML.

        Implementation notes:
            The stylesheet is inlined rather than linked so the document is a single portable file that renders the same when emailed, archived, or fed to the PDF engine.
        """
        verbose_print("Building comprehensive HTML document header", self.verbose)
        css_preview = self._get_comprehensive_css()[:120]
        css_preview_oneline = css_preview.replace('\n', ' ')
        verbose_print(f"CSS preview (first 120 chars): {css_preview_oneline}", self.verbose)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{APP_NAME} Analysis Report</title>
    {FAVICON_LINK_TAG}
    <style>
        {self._get_comprehensive_css()}
    </style>
</head>
<body>
    <div class="container">"""

    def _get_comprehensive_css(self) -> str:
        """
        Purpose:
            Return the report's stylesheet.

        Returns:
            The CSS.

        Implementation notes:
            Severity colours are defined once here and referenced by class throughout, so the dot in the index and the badge on a finding cannot disagree. Print rules are included alongside the screen ones, so the browser's own print output matches the generated PDF.
        """
        return """
        @page {
            margin: 0.55in;
            size: A4;
            @bottom-center {
                content: "__APP_NAME__ - Page " counter(page);
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

        /* Exploit chains: the one finding type that is worse than it looks,
           so it is marked in the strongest colour on the page. */
        .callout.chain { background: #FBE9E4; color: #7A241D; }
        .callout.chain .callout-label { color: #B3261E; }
        .chain-components { margin: 0 0 6px 0; font-size: 8.4pt; }
        .chain-flow { margin: 0; padding-left: 18px; }
        .chain-flow li { margin-bottom: 3px; }
        .chain-pill {
            display: inline-block;
            font-size: 7.3pt;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            padding: 2px 7px;
            border-radius: 10px;
            margin-left: 8px;
            vertical-align: middle;
            background: #FBE9E4;
            color: #7A241D;
            border: 1px solid #E0654F;
        }

        /* Validation verdicts. Deliberately the quietest block on the card:
           it explains why a finding was demoted, and a demoted finding should
           not draw the eye away from the ones that were not. */
        .callout.gate { background: #F1F2F5; color: #4A5160; }
        .callout.gate .callout-label { color: #6A7280; }
        .gate-reasons, .gate-warnings { margin: 0; padding-left: 18px; font-size: 8.2pt; }
        .gate-warnings { margin-top: 5px; color: #6B5205; }
        .gate-chained { margin: 6px 0 0 0; font-size: 8.2pt; color: #7A241D; }
        /* Cross-references. Muted on purpose: an unconfirmed pairing must not
           compete visually with a confirmed chain. */
        .related-findings { margin: 4px 0 0 0; padding-left: 18px; font-size: 8.2pt; }
        .related-findings li { margin-bottom: 4px; }
        .related-loc { color: #5F6368; font-family: monospace; font-size: 7.8pt; }
        .related-reason { color: #5F6368; font-style: italic; }
        /* An incomplete scan says so before anything else on the page. */
        .callout.coverage { background: #FFF4E5; color: #7A4A00; }
        .callout.coverage .callout-label { color: #B26A00; }

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
        """.replace("__APP_NAME__", APP_NAME) + SYNTAX_CSS

    def _build_report_header(self, detection_result: DetectionResult, vulnerabilities: List[Dict], is_unsupported: bool) -> str:
        """
        Purpose:
            Build the report banner: what was analysed, when, and the headline score.

        Parameters:
            detection_result: Detection output.
            vulnerabilities: The findings.
            is_unsupported: Whether the framework is unsupported.

        Returns:
            The header HTML.
        """
        verbose_print("Building report header", self.verbose)

        counts = self._count_by_severity(vulnerabilities)

        chips_html = ""
        if not is_unsupported:
            for severity in SEVERITY_ORDER:
                chips_html += (
                    f'<span class="chip"><span class="dot {severity}"></span>'
                    f'<span class="chip-count">{counts[severity]}</span> {SEVERITY_LABELS[severity]}</span>'
                )

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
            <p class="brand">{APP_NAME}</p>
            <div class="severity-chips">{chips_html}</div>
            <p class="tagline">Static application security analysis for Android &amp; iOS apps -
                surfacing insecure code paths, unsafe configuration, and hardening gaps
                before they reach production.</p>
            <h1 class="app-title">{_e(app_name)}</h1>
            <p class="app-id-line">App ID <strong>{_e(package_name)}</strong><span class="sep">|</span>Version <strong>{_e(version_name)}</strong></p>
        </div>"""

    def _target_basename(self, target_path: Optional[str]) -> str:
        """
        Purpose:
            Name the analysed target for display.

        Parameters:
            target_path: The analysed path.

        Returns:
            The basename, or a placeholder.

        Implementation notes:
            Trailing separators are stripped first, so a directory target yields its own name rather than an empty string.
        """
        if not target_path:
            return "Unknown application"
        return os.path.basename(target_path.rstrip('/')) or target_path

    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """
        Purpose:
            Count findings per severity.

        Parameters:
            vulnerabilities: The findings.

        Returns:
            A count for every severity, including zeros.

        Implementation notes:
            Every severity is present even at zero, so the statistics section renders a complete row rather than omitting the levels with no findings -- which would make a clean result look like a partial one.
        """
        counts = {s: 0 for s in SEVERITY_ORDER}
        for vuln in vulnerabilities:
            counts[_normalize_severity(vuln.get('severity'))] += 1
        return counts

    def _build_coverage_notice(self, analyzer_results: Optional[Dict]) -> str:
        """
        Purpose:
            Warn the reader when the AI analysis phase did not finish.

        Parameters:
            analyzer_results: Per-analyzer detail, carrying coverage.

        Returns:
            The notice HTML, empty when coverage was complete.

        Implementation notes:
            This is the most important caveat in the report. An analysis that stopped early produces fewer findings, and without this notice that reads as a safer app rather than a shorter scan. The notice states which part is still trustworthy -- the deterministic scanners ran to completion -- so the reader can calibrate rather than discarding the whole report.
        """
        coverage = (analyzer_results or {}).get('agent_coverage') or {}
        if not coverage or coverage.get('complete', True):
            return ''
        reason = _html.escape(str(coverage.get('degraded_reason') or
                                  'the AI phase did not finish'))
        incomplete = coverage.get('regions_incomplete', 0)
        total = coverage.get('regions_total', 0)
        scope = (f'{incomplete} of {total} code regions were not fully examined'
                 if total else 'part of the code was not fully examined')
        return f"""
        <div class="section">
            <div class="callout coverage">
                <span class="callout-label">Incomplete analysis</span>
                <p>The AI analysis phase stopped early because {reason}, so
                   {scope}. Findings from the deterministic scanners are
                   complete; model-sourced findings may be missing.</p>
            </div>
        </div>"""

    def _build_scope_notice(self, analyzer_results: Optional[Dict]) -> str:
        """
        Purpose:
            Warn the reader when some cited source could not be located.

        Parameters:
            analyzer_results: Per-analyzer detail, carrying scope counts.

        Returns:
            The notice HTML, empty when everything was resolved.

        Implementation notes:
            Findings whose source could not be found are downgraded rather than dropped, so they appear in the report with a weaker verdict. This notice explains why several findings look under-evidenced.
        """
        coverage = (analyzer_results or {}).get('agent_coverage') or {}
        scope = coverage.get('scope') or {}
        missing = int(scope.get('source_missing') or 0)
        checked = int(scope.get('source_checked') or 0)
        if not missing:
            return ''

        points = [
            f'<li><strong>{missing} of {checked}</strong> app classes have no file in '
            'the decompiled output, so their source could not be reviewed. They remain '
            'in the call graph - their callers and callees are still correct - but no '
            'one could read them.</li>']
        return f"""
        <div class="section">
            <div class="callout coverage">
                <span class="callout-label">Incomplete source</span>
                <p>The app\'s own code was mapped from the DEX, but part of it was not
                   readable in the decompiled tree:</p>
                <ul>{''.join(points)}</ul>
            </div>
        </div>"""

    def _build_limitation_notice(self, analyzer_results: Optional[Dict]) -> str:
        """
        Purpose:
            Warn the reader when part of the app could only be read in reduced form.

        Parameters:
            analyzer_results: Per-analyzer detail, carrying the limitation.

        Returns:
            The notice HTML, empty when there is no limitation.

        Implementation notes:
            A Flutter build Blutter cannot disassemble is analysed from its strings, platform layer and native libraries; the findings are real, but the Dart program logic was never read, so their absence there says nothing about it.
        """
        limitation = str((analyzer_results or {}).get('limitation') or '').strip()
        if not limitation:
            return ''
        return f"""
        <div class="section">
            <div class="callout coverage">
                <span class="callout-label">Reduced coverage</span>
                <p>{_html.escape(limitation)}</p>
            </div>
        </div>"""

    def _build_failed_notice(self, analyzer_results: Dict) -> str:
        """
        Purpose:
            Explain that the analysis of a supported framework did not run.

        Parameters:
            analyzer_results: Per-analyzer detail, carrying the reason.

        Returns:
            The notice HTML.
        """
        reason = str(analyzer_results.get('error') or 'The analyzer gave no reason.')
        return f"""
        <div class="section">
            <h2>Vulnerability Analysis</h2>
            <div class="notice-card">
                <h3>The analysis did not run</h3>
                <p>{_html.escape(reason)}</p>
                <p>No findings are listed because the app's code was not analysed, not because
                    it is free of issues.</p>
            </div>
        </div>"""

    def _build_unsupported_notice(self, analyzer_results: Dict) -> str:
        """
        Purpose:
            Explain that the app's framework is not one this tool analyses deeply.

        Parameters:
            analyzer_results: Per-analyzer detail.

        Returns:
            The notice HTML.

        Implementation notes:
            Without this, a report on an unsupported framework shows no findings and reads as a clean bill of health, which is the most misleading output this tool could produce. A supported framework whose decompiler is not configured is routed here too, by the same flag, and gets the failure notice with its reason instead: telling the reader its analysis is "under development" would be false.
        """
        framework_name = analyzer_results.get('framework', 'this framework')
        if analyzer_results.get('decompilation_status') == 'Tool Not Configured':
            return self._build_failed_notice(analyzer_results)
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
        """
        Purpose:
            Build the statistics section, showing the severity distribution.

        Parameters:
            vulnerabilities: The findings to render.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            Presented as a distribution rather than a single total, because the shape of a result set matters more than its size: twenty low findings and one critical are not comparable.
        """
        verbose_print("Building statistics section", self.verbose)

        total = len(vulnerabilities)
        counts = self._count_by_severity(vulnerabilities)

        security_score = calculate_security_score(counts)

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
        """
        Purpose:
            Group findings by title for the index, keeping the worst severity in each group.

        Parameters:
            vulnerabilities: The findings.

        Returns:
            Groups with title, severity and count, sorted by severity then by count.

        Implementation notes:
            Grouping keeps the index readable for an app with the same issue in fifty files, where an ungrouped list would be unusable. A group takes the highest severity of its members rather than the first or the most common, so a critical instance is never hidden behind a group labelled medium. Sorting by severity, then descending count, then title gives a stable order that is also the order a reader wants -- worst first, most widespread first within that.
        """
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
        """
        Purpose:
            Build the index of finding categories.

        Parameters:
            vulnerabilities: The findings to render.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            The empty case renders an explicit statement that nothing was found, rather than an empty table -- which a reader cannot distinguish from a rendering failure.
        """
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
        """
        Purpose:
            Order findings for the detail section.

        Parameters:
            vulnerabilities: The findings.

        Returns:
            The findings, worst first.

        Implementation notes:
            Severity leads and title breaks ties, so two runs over the same app produce the same order and the reports can be diffed.
        """
        def key(vuln: Dict):
            """
            Purpose:
                Sort key placing the most severe findings first.

            Parameters:
                vuln: The finding.

            Returns:
                A comparable key of severity rank and lowercased title.

            Implementation notes:
                Title is lowercased so ordering does not depend on capitalisation, which varies between the rule engine and model output.
            """
            severity = _normalize_severity(vuln.get('severity'))
            title = vuln.get('title') or vuln.get('vulnerability_type') or ''
            return (_SEVERITY_RANK[severity], title.lower())
        return sorted(vulnerabilities, key=key)

    def _build_vulnerability_details(self, vulnerabilities: List[Dict]) -> str:
        """
        Purpose:
            Build the detailed findings section.

        Parameters:
            vulnerabilities: The findings to render.

        Returns:
            The section HTML, empty when there is nothing to show.
        """
        verbose_print("Building vulnerability details", self.verbose)

        if not vulnerabilities:
            return ""

        items_html = "".join(self._format_vulnerability_item(v) for v in self._sorted_vulnerabilities(vulnerabilities))

        return f"""
        <div class="section">
            <h2>Vulnerabilities in the Code</h2>
            {items_html}
        </div>"""

    def _build_refuted_section(self, refuted: List[Dict]) -> str:
        """
        Purpose:
            Show the findings that were refuted or set aside, with the reasons.

        Parameters:
            refuted: The set-aside findings.

        Returns:
            The section HTML, empty when there were none.

        Implementation notes:
            These are kept in the report rather than deleted. A reader needs to see what was considered and why it was dismissed -- both to trust the result and to disagree with a dismissal they think is wrong.
        """
        if not refuted:
            return ""

        items_html = "".join(
            self._format_vulnerability_item(v)
            for v in self._sorted_vulnerabilities(refuted))

        return f"""
        <div class="section">
            <details class="refuted-section" open>
                <summary><h2 style="display:inline">Refuted Findings ({len(refuted)})</h2></summary>
                <p class="status-note">The tool's own evidence gate checked each of these
                   against the code it cited and found none of the construct the title
                   claims - before any model was asked to weigh in. Kept here, out of
                   the counts above, so a fabrication is visible rather than silently
                   discarded.</p>
                {items_html}
            </details>
        </div>"""

    def _render_code_table(self, lines: List[str], first_line: int, highlight_start: Optional[int],
                             highlight_end: Optional[int], filename: str,
                             lines_html: Optional[List[str]] = None) -> str:
        """
        Purpose:
            Render source lines as a numbered table with the vulnerable lines highlighted.

        Parameters:
            lines: The source lines.
            first_line: Line number of the first line.
            highlight_start: First line to highlight, or None.
            highlight_end: Last line to highlight, or None.
            filename: Used to select a syntax lexer.
            lines_html: Pre-highlighted lines, used when supplied and consistent in length.

        Returns:
            The code block HTML.

        Implementation notes:
            Real line numbers are shown rather than an offset, so a reader can open the file and go straight to the cited line. Pre-highlighted lines are accepted to avoid re-highlighting, but only when their count matches the source lines -- a mismatch would shift every line number in the block, so the block is re-highlighted instead. Empty lines render a non-breaking space so the table row keeps its height and the numbering stays aligned.

        Security considerations:
            The lines are escaped by the highlighter on both its paths before reaching this table.
        """
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
        """
        Purpose:
            Render the code evidence for a finding, from whichever form it carries.

        Parameters:
            vuln: The finding.

        Returns:
            The code block HTML, empty when the finding carries no code.

        Implementation notes:
            Structured context is preferred when present, since it carries real line numbers and the surrounding lines that make the cited one intelligible. A bare snippet is the fallback, and its line numbers are derived from the finding's reported line so the numbering is still meaningful rather than starting at one.
        """
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
        """
        Purpose:
            Build a link to the CWE entry for a finding.

        Parameters:
            cwe: The CWE identifier in any spelling.

        Returns:
            The URL, or None when no number could be found.

        Implementation notes:
            The number is extracted by pattern rather than by stripping a prefix, because the identifier arrives in several spellings from the taxonomy and from model output.
        """
        if not cwe:
            return None
        match = re.search(r'(\d+)', cwe)
        if not match:
            return None
        return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"

    def _format_vulnerability_item(self, vuln: Dict) -> str:
        """
        Purpose:
            Render one finding in full: its severity, location, description, evidence, verdict and remediation.

        Parameters:
            vuln: The finding.

        Returns:
            The finding HTML.

        Implementation notes:
            The CVSS pill is the base score of the vector the finding was reported with. Validation can lower the severity below that score's band -- a class ceiling, a development-host cap, a demotion to Informational -- so when the two disagree the pill says the score is the reported one; a bare "CVSS 9.1" beside a Low badge read as a contradiction.

        Security considerations:
            Every field is escaped. This is where the largest amount of attacker-influenced text -- titles, paths, descriptions and code -- enters the document.
        """
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
        if cvss_score is None:
            cvss_pill_html = ''
        elif _normalize_severity(severity_from_score(cvss_score)) != severity:
            cvss_pill_html = (
                f'<span class="cvss-pill" title="The base score of the vector as reported; '
                f'validation set the severity to {_e(severity)}">CVSS {cvss_score:.1f} as reported</span>')
        else:
            cvss_pill_html = f'<span class="cvss-pill">CVSS {cvss_score:.1f}</span>'
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

        chain_pill_html, chain_html = self._format_chain(vuln)
        related_html = self._format_related(vuln)
        gate_html = self._format_gate_result(vuln)

        return f"""
            <div class="vuln-item {severity}">
                <div class="vuln-item-head">
                    <span class="dot {severity}"></span><span class="vuln-item-title">{title}</span>{cvss_pill_html}{chain_pill_html}{dyn_pill_html}
                </div>
                {cvss_vector_html}
                {found_in}
                {chain_html}
                {code_block}
                <h4>Vulnerability Description</h4>
                <p>{description}</p>
                {impact_html}
                {exploitation_html}
                {dyn_callout_html}
                {recommendation_html}
                {references_html}
                {related_html}
                {gate_html}
            </div>"""

    def _format_related(self, vuln: Dict) -> str:
        """
        Purpose:
            Render the findings related to this one.

        Parameters:
            vuln: The finding.

        Returns:
            The related-findings HTML, empty when there are none.

        Implementation notes:
            Confirmed relationships are distinguished from candidates, so a reader can tell a verified chain partner from a proximity hint.
        """
        related = vuln.get('related_findings')
        if not isinstance(related, list) or not related:
            return ''
        rows = []
        for item in related[:5]:
            if not isinstance(item, dict):
                continue
            ref = item.get('with') or {}
            where = _html.escape(str(ref.get('file') or ''))
            line = _html.escape(str(ref.get('line') or ''))
            label = _html.escape(str(ref.get('title') or 'Related finding'))
            reason = _html.escape(str(item.get('reason') or ''))
            locus = f'{where}:{line}' if where and line else where
            rows.append(
                f'<li><strong>{label}</strong>'
                + (f' <span class="related-loc">{locus}</span>' if locus else '')
                + f'<br><span class="related-reason">{reason}</span></li>')
        if not rows:
            return ''
        return ('<h4>Related findings</h4>'
                '<ul class="related-findings">' + ''.join(rows) + '</ul>')

    def _format_chain(self, vuln: Dict) -> "tuple[str, str]":
        """
        Purpose:
            Render a chain finding's components and attack path.

        Parameters:
            vuln: The finding.

        Returns:
            A pair of HTML fragments for the chain's parts of the item.

        Implementation notes:
            The attack path is rendered as numbered steps, because the value of a chain finding is that a reader can follow the route through their own code rather than take the conclusion on trust.
        """
        chain = vuln.get('chain')
        if not isinstance(chain, dict):
            return '', ''

        pill = '<span class="chain-pill">Exploit Chain</span>'
        parts = []
        components = [c for c in (chain.get('components') or []) if c]
        if components:
            joined = _e(" + ".join(str(c) for c in components))
            parts.append(f'<p class="chain-components">Combines: {joined}</p>')
        flow = [str(step) for step in (chain.get('flow') or []) if str(step).strip()]
        if flow:
            steps = "".join(f'<li>{_e(step)}</li>' for step in flow)
            parts.append(f'<ol class="chain-flow">{steps}</ol>')
        if not parts:
            return pill, ''

        label = "Exploit chain" + (" - high priority" if chain.get('priority') else "")
        body = "".join(parts)
        return pill, (f'<div class="callout chain">'
                      f'<span class="callout-label">{label}</span>{body}</div>')

    def _format_gate_result(self, vuln: Dict) -> str:
        """
        Purpose:
            Render the verdict a finding received and the reasons behind it.

        Parameters:
            vuln: The finding.

        Returns:
            The verdict HTML, empty when there is nothing to show.

        Implementation notes:
            Showing the reasons is what makes the report auditable. A downgraded or refuted finding with no explanation is indistinguishable from an arbitrary one, and a reader who disagrees needs to see the argument to overrule it.
        """
        gate = vuln.get('gate_result')
        if not isinstance(gate, dict):
            return ''

        verdict = str(gate.get('verdict') or 'PASS')
        reasons = [str(r) for r in (gate.get('reasons') or []) if str(r).strip()]
        warnings = [str(w) for w in (gate.get('warnings') or []) if str(w).strip()]
        if verdict == 'PASS' and not reasons and not warnings:
            return ''

        labels = {
            'CHAIN_REQUIRED': 'Not independently reportable',
            'FALSE_POSITIVE': 'Reviewed against the source - not confirmed',
            'INFORMATIONAL': 'Reported as information',
            'DOWNGRADE': 'Severity reduced',
        }
        label = labels.get(verdict, 'Review notes')
        if verdict == 'FALSE_POSITIVE' and gate.get('mechanically_refuted'):
            label = 'Refuted mechanically - the cited code does not contain the claimed construct'

        original = str(gate.get('original_severity') or '')
        final = str(gate.get('final_severity') or '')
        if original and final and original != final:
            label += f' - {_e(original)} to {_e(final)}'
        rule = str(gate.get('weak_class_rule') or '')
        if rule:
            label += f' ({_e(rule)})'

        body = ''
        if reasons:
            body += '<ul class="gate-reasons">' + "".join(
                f'<li>{_e(r)}</li>' for r in reasons) + '</ul>'
        if warnings:
            body += '<ul class="gate-warnings">' + "".join(
                f'<li>{_e(w)}</li>' for w in warnings) + '</ul>'

        chained = [str(c) for c in (vuln.get('chained_into') or []) if str(c).strip()]
        if chained:
            body += (f'<p class="gate-chained">Confirmed as part of exploit chain '
                     f'{_e(", ".join(chained))} - see that finding for the full path.</p>')

        return (f'<div class="callout gate"><span class="callout-label">{label}</span>'
                f'{body}</div>')

    def _format_dynamic_verification(self, vuln: Dict) -> "tuple[str, str]":
        """
        Purpose:
            Render the on-device verdict for a finding.

        Parameters:
            vuln: The finding.

        Returns:
            A pair of HTML fragments for the verification parts of the item.

        Implementation notes:
            A runtime verdict is shown distinctly from the static verdict, because a finding confirmed on a real device is a materially stronger claim and a reader should be able to see which is which. Findings marked not verified carry their reason, so an unverified finding reads as unexamined rather than as disproved; a refuted one shows what the device did that disproved it.
        """
        dv = vuln.get('dynamic_verification')
        if not isinstance(dv, dict) or not dv.get('status'):
            return '', ''

        status = dv.get('status')
        if status == 'verified':
            pill = '<span class="dyn-pill verified">Dynamic Verified</span>'
            evidence = _e(dv.get('evidence', ''))
            callout = (
                f'<div class="callout dyn-verified">'
                f'<span class="callout-label">Dynamic Verification - Verified</span>{evidence}</div>'
                if evidence else ''
            )
            return pill, callout

        if status == 'refuted':
            pill = '<span class="dyn-pill unverified">Dynamic Refuted</span>'
            evidence = _e(dv.get('evidence', ''))
            callout = (
                f'<div class="callout dyn-unverified">'
                f'<span class="callout-label">Dynamic Verification - Refuted on the device</span>{evidence}</div>'
                if evidence else ''
            )
            return pill, callout

        label = 'Dynamic - Not Run' if status == 'not_attempted' else 'Dynamic - Unverified'
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
        """
        Purpose:
            Build the application information section.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML.
        """
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
        """
        Purpose:
            Build the grid of the app's declared identity, versions and SDK levels.

        Parameters:
            detection_result: Detection output.

        Returns:
            The grid HTML.

        Implementation notes:
            The target SDK is shown because several findings' severity depends on it; a reader checking a platform-default caveat needs the number in the same document.
        """
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
        """
        Purpose:
            Build the declared components section.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when the app declares none.

        Security considerations:
            Component class names come from the manifest and are escaped before display.
        """
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
        """
        Purpose:
            Collapse repeated framework detections for display.

        Parameters:
            detection_result: Detection output.

        Returns:
            The distinct frameworks with their confidences.

        Implementation notes:
            Several detectors report the same framework, so an ungrouped list would show it two or three times with different confidences and suggest an ambiguity that does not exist.
        """
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
        """
        Purpose:
            Describe what the analysis actually did -- which analyzers ran, over what, and with what coverage.

        Parameters:
            detection_result: Detection output.
            analyzer_results: Per-analyzer detail.

        Returns:
            The section HTML.

        Implementation notes:
            This is what lets a reader judge the report's weight. A result set means something different depending on whether the AI pass ran, whether the source resolved, and which analyzers applied, and stating it explicitly is what separates a security report from a list of assertions.
        """
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
        """
        Purpose:
            Build the report footer.

        Returns:
            The footer HTML.

        Implementation notes:
            Carries the tool name, version and timestamp, so a report separated from its scan still states what produced it.
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""
        <div class="report-footer">
            <p>Generated by {APP_NAME} v{APP_VERSION} &bull; {timestamp}</p>
            <p><a href="{HOMEPAGE}">{HOMEPAGE}</a></p>
        </div>
    </div>
</body>
</html>"""
