#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.html_content_builder

Purpose:
    Build the detection-only HTML report: what the app is, which framework it uses, what it declares, and what went wrong during analysis.

Responsibilities:
    Assemble the document from per-section builders.

Dependencies:
    The metadata module for the product name and version.

Implementation notes:
    Sections are built independently and concatenated, each returning an empty string when it has nothing to show. That keeps the report free of empty headings for an app that declares no components or produced no warnings. This is the simpler of the two HTML builders; the comprehensive one produces the full findings report.

Security considerations:
    Values from the analysed APK -- package name, app label, component class names -- are interpolated into HTML here without escaping. An app declaring a label containing markup would have it rendered rather than displayed. Anything reading this report should treat it as generated from untrusted input, and this builder would be the place to add escaping.
"""

from datetime import datetime
from lu77U_MobileSec.detection.results import DetectionResult
from .._metadata import HOMEPAGE
from ..config.settings import APP_NAME, APP_VERSION
from ..config.branding import FAVICON_LINK_TAG
from ..utils.verbose import verbose_print

class HTMLContentBuilder:
    """
    Purpose:
        Builds the detection-only HTML report.

    Attributes:
        verbose: Whether building is traced.

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
        verbose_print("HTMLContentBuilder initialized", self.verbose)
    
    def build_html_content(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Assemble the complete report document.

        Parameters:
            detection_result: Detection output.

        Returns:
            The report HTML.

        Implementation notes:
            Sections are appended in reading order -- overview, framework, application detail, issues -- so the reader meets the app's identity before the detail.
        """
        verbose_print("Starting HTML content building", self.verbose)
        verbose_print(f"Building report for target: {detection_result.target_path}", self.verbose)
        
        html = self._build_html_header()
        verbose_print("HTML header built", self.verbose)
        
        html += self._build_overview_section(detection_result)
        verbose_print("Overview section built", self.verbose)
        
        html += self._build_framework_section(detection_result)
        verbose_print("Framework section built", self.verbose)
        
        html += self._build_app_info_section(detection_result)
        verbose_print("App info section built", self.verbose)
        
        html += self._build_issues_section(detection_result)
        verbose_print("Issues section built", self.verbose)
        
        html += self._build_footer()
        verbose_print("Footer built", self.verbose)
        
        verbose_print(f"HTML content building complete - total length: {len(html)} characters", self.verbose)
        return html
    
    def _build_html_header(self) -> str:
        """
        Purpose:
            Build the document head and the report banner.

        Returns:
            The opening HTML.

        Implementation notes:
            Carries the generation timestamp, so a printed or saved report states when it was produced rather than being undatable.
        """
        verbose_print("Building HTML document header", self.verbose)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        verbose_print(f"Generated timestamp: {timestamp}", self.verbose)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{APP_NAME} Analysis Report</title>
    {FAVICON_LINK_TAG}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📱 {APP_NAME} Analysis Report</h1>
            <p class="subtitle">Mobile Security Analysis Tool</p>
            <p class="timestamp">Generated: {timestamp}</p>
        </div>"""
    
    def _build_overview_section(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the overview section, naming the app and the target analysed of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            A missing package name renders as a placeholder rather than an empty cell, so a report on an app whose manifest could not be read still reads coherently.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        verbose_print("Building overview section", self.verbose)
        
        package_name = "N/A"
        if detection_result.basic_info and detection_result.basic_info.package_name:
            package_name = detection_result.basic_info.package_name
            verbose_print(f"Package name found: {package_name}", self.verbose)
        else:
            verbose_print("No package name available", self.verbose)
        
        target_type = 'APK File' if detection_result.is_apk else 'Project Directory'
        verbose_print(f"Target type: {target_type}", self.verbose)
        
        duration = detection_result.get_formatted_duration()
        verbose_print(f"Analysis duration: {duration}", self.verbose)
        
        timestamp_str = detection_result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S') if detection_result.analysis_timestamp else 'N/A'
        verbose_print(f"Analysis timestamp: {timestamp_str}", self.verbose)
        
        return f"""
        <div class="section">
            <h2>📊 Analysis Overview</h2>
            <div class="info-grid">
                <div class="info-row">
                    <div class="info-label">Package Name:</div>
                    <div class="info-value">{package_name}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Target Type:</div>
                    <div class="info-value">{target_type}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Analysis Duration:</div>
                    <div class="info-value">{duration}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Analysis Timestamp:</div>
                    <div class="info-value">{timestamp_str}</div>
                </div>
            </div>
        </div>"""
    
    def _build_framework_section(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the framework detection section of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        verbose_print("Building framework detection section", self.verbose)
        
        html = """
        <div class="section">
            <h2>🔍 Framework Detection Results</h2>"""
        
        if detection_result.framework_results:
            verbose_print("Framework results available - building detailed sections", self.verbose)
            html += self._build_framework_summary(detection_result)
            html += self._build_detected_frameworks_list(detection_result)
            html += self._build_confidence_scores(detection_result)
        else:
            verbose_print("No framework results available", self.verbose)
            html += '<p class="status-warning">No framework detection results available</p>'
        
        html += "</div>"
        return html
    
    def _build_framework_summary(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the framework summary, naming the primary framework and how many were detected of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        primary = detection_result.framework_results.get_primary_framework_name()
        detected_count = len(detection_result.framework_results.detected_frameworks)
        return f"""
            <div class="summary-box">
                <h3>Detection Summary</h3>
                <div class="info-grid">
                    <div class="info-row">
                        <div class="info-label">Primary Framework:</div>
                        <div class="info-value"><strong>{primary}</strong></div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Total Frameworks Detected:</div>
                        <div class="info-value">{detected_count}</div>
                    </div>
                </div>
            </div>"""
    
    def _build_detected_frameworks_list(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the list of detected frameworks of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            Entries are read defensively because detectors return both dict and object shapes. Returns empty when nothing was detected, so no heading appears over an empty list.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        if not detection_result.framework_results.detected_frameworks:
            return ""
        html = "<h3>Detected Frameworks</h3>"
        for i, framework in enumerate(detection_result.framework_results.detected_frameworks, 1):
            if isinstance(framework, dict):
                name = framework.get('framework', 'Unknown')
                confidence = framework.get('confidence', 0)
                html += f'''<div class="framework-item">
                    <strong>{i}. {name}</strong>
                    <span style="float: right; color: #3498db;">Confidence: {confidence:.1%}</span>
                </div>'''
            else:
                html += f'<div class="framework-item"><strong>{i}. {framework}</strong></div>'
        return html
    
    def _build_confidence_scores(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the per-framework confidence scores of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            Shown as percentages, and every framework considered is listed rather than only the winner, so a reader can see whether the detection was clear-cut.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        if not detection_result.framework_results.confidence_scores:
            return ""
        html = "<h3>Confidence Scores</h3>"
        html += '<div class="component-list">'
        for framework, score in detection_result.framework_results.confidence_scores.items():
            html += f'<div><strong>{framework}:</strong> {score:.1%}</div>'
        html += '</div>'
        return html
    
    def _build_app_info_section(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the application information section of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        html = """
        <div class="section">
            <h2>📋 Application Information</h2>"""
        if detection_result.basic_info:
            html += self._build_basic_info_grid(detection_result)
            html += self._build_components_section(detection_result)
        else:
            html += '<p class="status-warning">No application information available</p>'
        html += "</div>"
        return html
    
    def _build_basic_info_grid(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the grid of the app's declared identity, versions and SDK levels of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            Each row is emitted only when its value is present, so an app that declares little produces a short grid rather than a column of placeholders.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        html = '<div class="info-grid">'
        basic_info = detection_result.basic_info
        if basic_info.app_name:
            html += f'''<div class="info-row">
                <div class="info-label">Application Name:</div>
                <div class="info-value">{basic_info.app_name}</div>
            </div>'''
        if basic_info.package_name:
            html += f'''<div class="info-row">
                <div class="info-label">Package Name:</div>
                <div class="info-value">{basic_info.package_name}</div>
            </div>'''
        if basic_info.version_name:
            html += f'''<div class="info-row">
                <div class="info-label">Version Name:</div>
                <div class="info-value">{basic_info.version_name}</div>
            </div>'''
        if basic_info.version_code:
            html += f'''<div class="info-row">
                <div class="info-label">Version Code:</div>
                <div class="info-value">{basic_info.version_code}</div>
            </div>'''
        html += f'''<div class="info-row">
            <div class="info-label">File Size:</div>
            <div class="info-value">{basic_info.get_file_size_formatted()}</div>
        </div>'''
        if basic_info.file_type:
            html += f'''<div class="info-row">
                <div class="info-label">File Type:</div>
                <div class="info-value">{basic_info.file_type}</div>
            </div>'''
        if basic_info.min_sdk:
            html += f'''<div class="info-row">
                <div class="info-label">Minimum SDK:</div>
                <div class="info-value">{basic_info.min_sdk}</div>
            </div>'''
        if basic_info.target_sdk:
            html += f'''<div class="info-row">
                <div class="info-label">Target SDK:</div>
                <div class="info-value">{basic_info.target_sdk}</div>
            </div>'''
        html += '</div>'
        return html
    
    def _build_components_section(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the declared components section of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            Returns empty when the app declares no components, which usually means the manifest could not be parsed rather than that the app has none.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        basic_info = detection_result.basic_info
        component_count = basic_info.get_component_count()
        if component_count == 0:
            return ""
        html = f'<h3>Android Components ({component_count} total)</h3>'
        html += '<div class="component-list">'
        html += self._build_component_list("Activities", basic_info.activities)
        html += self._build_component_list("Services", basic_info.services)
        html += self._build_component_list("Broadcast Receivers", basic_info.receivers)
        html += self._build_component_list("Content Providers", basic_info.providers)
        html += '</div>'
        return html
    
    def _build_component_list(self, component_type: str, components: list) -> str:
        """
        Purpose:
            Build the list for one kind of declared component.

        Parameters:
            component_type: The component kind, used as the heading.
            components: The declared class names.

        Returns:
            The list HTML, empty when there are none.

        Security considerations:
            Component class names come from the app's manifest and are interpolated without escaping; see the module note.
        """
        verbose_print(f"Building component list for {component_type}: {len(components)} items", self.verbose)
        
        if not components:
            verbose_print(f"No {component_type.lower()} found", self.verbose)
            return ""
            
        html = f'<div><strong>{component_type} ({len(components)}):</strong></div>'
        html += '<ul>'
        
        for i, component in enumerate(components):
            html += f'<li>{component}</li>'
            if i == 0:
                verbose_print(f"First {component_type.lower()}: {component}", self.verbose)
        
        html += '</ul>'
        verbose_print(f"Component list for {component_type} completed", self.verbose)
        return html
    
    def _build_issues_section(self, detection_result: DetectionResult) -> str:
        """
        Purpose:
            Build the analysis issues section, listing errors and warnings gathered during detection of the report.

        Parameters:
            detection_result: Detection output.

        Returns:
            The section HTML, empty when there is nothing to show.

        Implementation notes:
            Returns empty when the scan was clean. Showing these matters: a report that omitted them would present a partial analysis as a complete one.

        Security considerations:
            Values interpolated here originate in the analysed APK and are not escaped by this builder; see the module note.
        """
        if not (detection_result.errors or detection_result.warnings):
            return ""
        html = """
        <div class="section">
            <h2>⚠️ Analysis Issues</h2>"""
        if detection_result.errors:
            html += f"<h3 class='status-error'>Errors ({len(detection_result.errors)})</h3>"
            html += '<div class="component-list"><ul>'
            for error in detection_result.errors:
                html += f'<li class="status-error">{error}</li>'
            html += "</ul></div>"
        if detection_result.warnings:
            html += f"<h3 class='status-warning'>Warnings ({len(detection_result.warnings)})</h3>"
            html += '<div class="component-list"><ul>'
            for warning in detection_result.warnings:
                html += f'<li class="status-warning">{warning}</li>'
            html += "</ul></div>"
        html += "</div>"
        return html
    
    def _build_footer(self) -> str:
        """
        Purpose:
            Build the report footer.

        Returns:
            The closing HTML.

        Implementation notes:
            Carries the tool name, version and timestamp, so a report separated from its scan still states what produced it -- which matters because findings and severities change between versions.
        """
        return f"""
        <div class="footer">
            <p>Generated by {APP_NAME} v{APP_VERSION} &bull; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For more information, visit: <a href="{HOMEPAGE}">{HOMEPAGE}</a></p>
        </div>
    </div>
</body>
</html>"""
