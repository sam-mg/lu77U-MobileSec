"""JSON Exporter for Analysis Results"""

import json
import os
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
from lu77U_MobileSec.detection.results import DetectionResult
from ..utils.verbose import verbose_print
from ..config.settings import APP_VERSION

class JSONExporter:
    """Export analysis results to JSON format"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        verbose_print("JSONExporter initialized", self.verbose)

    def export_analysis_results(self, detection_result: DetectionResult, output_path: str, vulnerability_results: Optional[Dict] = None, analyzer_results: Optional[Dict] = None, output_manager=None, write_html: bool = False) -> str:
        verbose_print("Starting JSON export", self.verbose)

        if write_html:
            try:
                self.save_html(detection_result=detection_result, output_path=output_path, vulnerability_results=vulnerability_results, analyzer_results=analyzer_results, output_manager=output_manager)
            except Exception as e:
                verbose_print(f"Warning: Failed to save HTML: {e}", self.verbose)

        if output_manager:
            json_path = output_manager.get_json_path()
        elif output_path and output_path.lower().endswith('.apk'):
            json_path = output_path.rsplit('.', 1)[0] + '_analysis.json'
        elif output_path and output_path.lower().endswith('.json'):
            json_path = output_path
        else:
            json_path = str(Path(output_path) / 'analysis_results.json')
            verbose_print(f"Default JSON path: {json_path}", self.verbose)
        
        verbose_print(f"JSON output path: {json_path}", self.verbose)
        metadata = self._build_metadata(detection_result)
        framework_detection = self._build_framework_data(detection_result)
        application_info = self._build_app_info(detection_result)
        vulnerability_analysis = self._build_vulnerability_data(vulnerability_results)
        summary = self._build_summary(detection_result, vulnerability_results)

        analysis_data = {
            'metadata': metadata,
            'framework_detection': framework_detection,
            'application_info': application_info,
            'vulnerability_analysis': vulnerability_analysis,
            'analyzer_details': analyzer_results or {},
            'summary': summary
        }
        
        try:
            parent_dir = os.path.dirname(json_path)
            if parent_dir and not os.path.exists(parent_dir):
                try:
                    os.makedirs(parent_dir, exist_ok=True)
                    verbose_print(f"Created parent directory for JSON: {parent_dir}", self.verbose)
                except Exception as e:
                    verbose_print(f"Failed to create parent directory for JSON: {e}", self.verbose)

            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, indent=2, ensure_ascii=False)

            return json_path
            
        except Exception as e:
            verbose_print(f"Failed to export JSON: {e}", self.verbose)
            raise
    
    def _build_metadata(self, detection_result: DetectionResult) -> Dict[str, Any]:
        """Build metadata section"""
        meta = {
            'tool': 'lu77U-MobileSec',
            'version': APP_VERSION,
            'timestamp': datetime.now().isoformat(),
            'target': getattr(detection_result, 'target_path', None),
            'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return meta
    
    def _build_framework_data(self, detection_result: DetectionResult) -> Dict[str, Any]:
        """Build framework detection data"""
        if not getattr(detection_result, 'framework_results', None):
            verbose_print("No framework results available", self.verbose)
            return {
                'detected': False,
                'primary_framework': 'Unknown',
                'frameworks': []
            }

        primary = detection_result.framework_results.get_primary_framework_name()
        all_frameworks = detection_result.framework_results.get_top_frameworks(10)

        primary_confidence = all_frameworks[0]['confidence'] if all_frameworks else 0.0

        frameworks_list = []
        for fw in all_frameworks:
            frameworks_list.append({
                'name': fw['name'],
                'confidence': fw['confidence'],
                'confidence_level': fw.get('confidence_level', 'Unknown'),
                'indicators_found': fw.get('indicators_found', [])
            })

        result = {
            'detected': primary != 'Unknown',
            'primary_framework': primary,
            'confidence': primary_confidence,
            'confidence_level': all_frameworks[0].get('confidence_level', 'Unknown') if all_frameworks else 'Unknown',
            'frameworks': frameworks_list
        }
        return result
    
    def _build_app_info(self, detection_result: DetectionResult) -> Dict[str, Any]:
        """Build application information"""
        basic_info = detection_result.basic_info

        if not basic_info:
            verbose_print("No basic_info present; returning N/A placeholders", self.verbose)
            return {
                'package_name': 'N/A',
                'app_name': 'N/A',
                'version_name': 'N/A',
                'version_code': 'N/A',
                'min_sdk': 'N/A',
                'target_sdk': 'N/A',
                'file_size': 'N/A',
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            }

        file_size = getattr(basic_info, 'file_size', 'N/A')
        try:
            file_size_mb = round(basic_info.get_file_size_mb(), 2) if hasattr(basic_info, 'get_file_size_mb') else 'N/A'
        except Exception as e:
            verbose_print(f"Failed to compute file_size_mb: {e}", self.verbose)
            file_size_mb = 'N/A'

        app_info = {
            'package_name': getattr(basic_info, 'package_name', 'N/A'),
            'app_name': getattr(basic_info, 'app_name', 'N/A'),
            'version_name': getattr(basic_info, 'version_name', 'N/A'),
            'version_code': getattr(basic_info, 'version_code', 'N/A'),
            'min_sdk': getattr(basic_info, 'min_sdk', 'N/A'),
            'target_sdk': getattr(basic_info, 'target_sdk', 'N/A'),
            'file_size': file_size,
            'file_size_mb': file_size_mb,
            'permissions': getattr(basic_info, 'permissions', []),
            'activities': getattr(basic_info, 'activities', []),
            'services': getattr(basic_info, 'services', []),
            'receivers': getattr(basic_info, 'receivers', []),
            'providers': getattr(basic_info, 'providers', [])
        }

        return app_info
    
    def _build_vulnerability_data(self, vulnerability_results: Optional[Dict]) -> Dict[str, Any]:
        """Build vulnerability analysis data"""
        if not vulnerability_results:
            verbose_print("No vulnerability results provided; marking as not analyzed", self.verbose)
            return {
                'analyzed': False,
                'vulnerabilities': []
            }

        vulnerabilities = vulnerability_results.get('vulnerabilities', [])
        analysis_success = vulnerability_results.get('analysis_success', False)

        by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity not in by_severity:
                severity = 'info'
            # Try to get title from either 'title' or 'vulnerability_type' key
            title = vuln.get('title') or vuln.get('vulnerability_type', 'Unknown')
            line_start = vuln.get('line_number', 0)
            line_end = vuln.get('line_end', 0) or line_start
            entry = {
                'title': title,
                'severity': vuln.get('severity', 'info'),
                'cvss_vector': vuln.get('cvss_vector'),
                'cvss_score': vuln.get('cvss_score'),
                'description': vuln.get('description', ''),
                'file': vuln.get('file', ''),
                'location': vuln.get('location', ''),
                'line': line_start,
                'line_start': line_start,
                'line_end': line_end,
                'impact': vuln.get('impact', ''),
                'code_snippet': vuln.get('code_snippet', ''),
                'code_context': vuln.get('code_context'),
                'exploitation': vuln.get('exploitation', ''),
                'recommendation': vuln.get('recommendation', ''),
                'cwe': vuln.get('cwe', ''),
                'owasp_mobile': vuln.get('owasp_mobile', ''),
                'dynamic_verification': vuln.get('dynamic_verification')
            }
            by_severity[severity].append(entry)

        counts = {k: len(v) for k, v in by_severity.items()}

        return {
            'analyzed': analysis_success,
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': counts,
            'vulnerabilities': by_severity
        }
    
    def _build_summary(self, detection_result: DetectionResult, vulnerability_results: Optional[Dict]) -> Dict[str, Any]:
        """Build analysis summary"""
        vuln_data = self._build_vulnerability_data(vulnerability_results)

        # Ensure keys exist in case of missing data
        by_sev = vuln_data.get('by_severity', {})
        critical = by_sev.get('critical', 0)
        high = by_sev.get('high', 0)
        medium = by_sev.get('medium', 0)
        low = by_sev.get('low', 0)

        security_score = self._calculate_security_score(vuln_data)
        verbose_print(f"Computed security_score for summary: {security_score}", self.verbose)

        return {
            'framework_detected': detection_result.framework_results is not None,
            'vulnerability_scan_complete': vuln_data.get('analyzed', False),
            'total_vulnerabilities': vuln_data.get('total_vulnerabilities', 0),
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'security_score': security_score
        }
    
    def _calculate_security_score(self, vuln_data: Dict[str, Any]) -> float:
        """Calculate overall security score (0-100)"""
        verbose_print("Calculating security score", self.verbose)
        
        if not vuln_data['analyzed']:
            verbose_print("Analysis not performed - returning 0.0 score", self.verbose)
            return 0.0
        
        score = 100.0
        verbose_print(f"Starting score: {score}", self.verbose)
        
        severity = vuln_data['by_severity']
        verbose_print(f"Severity counts: {severity}", self.verbose)
        
        score -= severity['critical'] * 20
        verbose_print(f"After critical ({severity['critical']}): {score}", self.verbose)
        
        score -= severity['high'] * 10
        verbose_print(f"After high ({severity['high']}): {score}", self.verbose)
        
        score -= severity['medium'] * 5
        verbose_print(f"After medium ({severity['medium']}): {score}", self.verbose)
        
        score -= severity['low'] * 2
        verbose_print(f"After low ({severity['low']}): {score}", self.verbose)
        
        score -= severity['info'] * 0.5
        verbose_print(f"After info ({severity['info']}): {score}", self.verbose)
        
        final_score = max(0.0, min(100.0, score))
        verbose_print(f"Final security score (clamped): {final_score}", self.verbose)
        
        return final_score
    
    def save_html(self, detection_result: DetectionResult, output_path: str, vulnerability_results: Optional[Dict] = None,  analyzer_results: Optional[Dict] = None, output_manager=None) -> str:
        verbose_print("Saving HTML file for unsupported framework", self.verbose)
        
        try:
            from .comprehensive_html_builder import ComprehensiveHTMLBuilder
            html_builder = ComprehensiveHTMLBuilder(verbose=self.verbose)
            
            html_content = html_builder.build_comprehensive_report(
                detection_result=detection_result,
                vulnerability_results=vulnerability_results,
                analyzer_results=analyzer_results
            )
            
            if output_manager:
                html_path = output_manager.get_html_path()
                verbose_print(f"Using OutputManager for HTML path", self.verbose)
            else:
                if output_path.lower().endswith('.apk'):
                    base_path = output_path.rsplit('.', 1)[0]
                else:
                    base_path = str(Path(output_path) / 'analysis_report')
                
                is_unsupported = analyzer_results and analyzer_results.get('unsupported_framework', False)
                framework_name = analyzer_results.get('framework', 'unknown') if analyzer_results else 'unknown'
                
                if is_unsupported:
                    html_path = f"{base_path}_unsupported_{framework_name.lower().replace(' ', '_')}.html"
                    verbose_print(f"Unsupported framework detected: {framework_name}", self.verbose)
                else:
                    html_path = f"{base_path}.html"
            
            html_dir = os.path.dirname(html_path)
            if html_dir and not os.path.exists(html_dir):
                os.makedirs(html_dir, exist_ok=True)
                verbose_print(f"Created directory: {html_dir}", self.verbose)
            
            verbose_print(f"Writing HTML to: {html_path}", self.verbose)
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            verbose_print(f"HTML saved successfully", self.verbose)
            verbose_print(f"HTML saved to: {html_path}", self.verbose)
            
            return html_path
            
        except Exception as e:
            verbose_print(f"Failed to save HTML: {e}", self.verbose)
            if self.verbose:
                import traceback
                traceback.print_exc()
            raise