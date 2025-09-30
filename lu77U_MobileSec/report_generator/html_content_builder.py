"""HTML Content Builder for PDF Reports"""

from datetime import datetime
from typing import Optional
from lu77U_MobileSec.detection.results import DetectionResult
from ..utils.verbose import verbose_print


class HTMLContentBuilder:
    """Builds HTML content for PDF reports from analysis results"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("HTMLContentBuilder initialized", self.verbose)
    
    def build_html_content(self, detection_result: DetectionResult) -> str:
        """Build enhanced HTML content for PDF report"""
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
        """Build HTML document header"""
        verbose_print("Building HTML document header", self.verbose)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        verbose_print(f"Generated timestamp: {timestamp}", self.verbose)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>lu77U-MobileSec Analysis Report</title>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📱 lu77U-MobileSec Analysis Report</h1>
            <p class="subtitle">Mobile Security Analysis Tool</p>
            <p class="timestamp">Generated: {timestamp}</p>
        </div>"""
    
    def _build_overview_section(self, detection_result: DetectionResult) -> str:
        """Build analysis overview section"""
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
        """Build framework detection results section"""
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
        """Build framework detection summary"""
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
        """Build list of detected frameworks"""
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
        """Build confidence scores section"""
        if not detection_result.framework_results.confidence_scores:
            return ""
        html = "<h3>Confidence Scores</h3>"
        html += '<div class="component-list">'
        for framework, score in detection_result.framework_results.confidence_scores.items():
            html += f'<div><strong>{framework}:</strong> {score:.1%}</div>'
        html += '</div>'
        return html
    
    def _build_app_info_section(self, detection_result: DetectionResult) -> str:
        """Build application information section"""
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
        """Build basic application information grid"""
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
        """Build Android components section"""
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
        """Build a list of all components without truncation"""
        verbose_print(f"Building component list for {component_type}: {len(components)} items", self.verbose)
        
        if not components:
            verbose_print(f"No {component_type.lower()} found", self.verbose)
            return ""
            
        html = f'<div><strong>{component_type} ({len(components)}):</strong></div>'
        html += '<ul>'
        
        for i, component in enumerate(components):
            html += f'<li>{component}</li>'
            if i == 0:  # Log first component as example
                verbose_print(f"First {component_type.lower()}: {component}", self.verbose)
        
        html += '</ul>'
        verbose_print(f"Component list for {component_type} completed", self.verbose)
        return html
    
    def _build_issues_section(self, detection_result: DetectionResult) -> str:
        """Build analysis issues section"""
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
        """Build HTML document footer"""
        return f"""
        <div class="footer">
            <p>Generated by lu77U-MobileSec v0.0.3 • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For more information, visit: <a href="https://github.com/sam-mg/lu77U-MobileSec">https://github.com/sam-mg/lu77U-MobileSec</a></p>
        </div>
    </div>
</body>
</html>"""
