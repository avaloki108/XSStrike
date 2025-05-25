"""
Report Generator for XSStrike.

This module provides comprehensive reporting capabilities with support for
multiple output formats (HTML, JSON, CSV) and different report types
including executive summaries, technical details, and compliance reports.
"""

import json
import csv
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from jinja2 import Template, Environment, FileSystemLoader
from urllib.parse import urlparse

from core.engine import ScanResult, ScanStatus
from core.knowledge_base import knowledge_base
from core.log import setup_logger

logger = setup_logger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_format: str = "html"  # html, json, csv, xml
    output_file: Optional[str] = None
    template_dir: str = "templates"
    include_details: bool = True
    include_payloads: bool = True
    include_statistics: bool = True
    include_recommendations: bool = True
    executive_summary: bool = False
    compliance_format: Optional[str] = None  # owasp, nist, etc.


@dataclass
class VulnerabilityReport:
    """Structured vulnerability report."""
    id: str
    title: str
    severity: str
    risk_score: float
    description: str
    url: str
    parameter: str
    payload: str
    evidence: str
    impact: str
    recommendation: str
    references: List[str]
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    discovered_at: Optional[str] = None


@dataclass
class ScanReport:
    """Complete scan report structure."""
    scan_id: str
    target_url: str
    scan_type: str
    started_at: str
    completed_at: str
    duration: float
    status: str
    vulnerabilities: List[VulnerabilityReport]
    statistics: Dict[str, Any]
    target_info: Dict[str, Any]
    scan_config: Dict[str, Any]
    ai_insights: Optional[Dict[str, Any]] = None
    recommendations: List[str] = None
    executive_summary: Optional[str] = None


class ReportGenerator:
    """
    Comprehensive report generator for XSStrike scan results.
    
    Supports multiple output formats and provides different report types
    for various audiences (technical, executive, compliance).
    """

    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.logger = setup_logger(__name__)
        self._ensure_template_directory()
        self._setup_jinja_environment()

    def _ensure_template_directory(self) -> None:
        """Ensure template directory exists."""
        self.template_dir.mkdir(parents=True, exist_ok=True)

        # Create default templates if they don't exist
        self._create_default_templates()

    def _setup_jinja_environment(self) -> None:
        """Setup Jinja2 environment for template rendering."""
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )

        # Add custom filters
        self.jinja_env.filters['severity_color'] = self._severity_color_filter
        self.jinja_env.filters['format_datetime'] = self._format_datetime_filter
        self.jinja_env.filters['format_duration'] = self._format_duration_filter

    def _create_default_templates(self) -> None:
        """Create default HTML templates."""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSStrike Scan Report - {{ report.target_url }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007bff; margin: 0; }
        .header .subtitle { color: #666; font-size: 18px; margin-top: 5px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff; }
        .card h3 { margin: 0 0 10px 0; color: #333; }
        .card .value { font-size: 24px; font-weight: bold; color: #007bff; }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .severity-info { color: #17a2b8; }
        .vulnerability { background: #fff; border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 20px; }
        .vuln-header { padding: 20px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; }
        .vuln-body { padding: 20px; }
        .vuln-title { font-size: 18px; font-weight: bold; margin: 0; }
        .vuln-meta { color: #666; font-size: 14px; margin-top: 5px; }
        .code-block { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 15px; font-family: monospace; overflow-x: auto; }
        .recommendations { background: #d4edda; border: 1px solid #c3e6cb; border-radius: 6px; padding: 20px; margin-top: 30px; }
        .recommendations h3 { color: #155724; margin-top: 0; }
        .ai-insights { background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 6px; padding: 20px; margin-top: 30px; }
        .ai-insights h3 { color: #0c5460; margin-top: 0; }
        .footer { border-top: 1px solid #dee2e6; padding-top: 20px; margin-top: 30px; text-align: center; color: #666; }
        .no-vulnerabilities { text-align: center; padding: 40px; color: #28a745; }
        .no-vulnerabilities i { font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ XSStrike Security Report</h1>
            <div class="subtitle">{{ report.target_url }}</div>
            <div style="margin-top: 10px; color: #666;">
                <strong>Scan ID:</strong> {{ report.scan_id }} | 
                <strong>Started:</strong> {{ report.started_at | format_datetime }} | 
                <strong>Duration:</strong> {{ report.duration | format_duration }}
            </div>
        </div>

        <div class="summary-cards">
            <div class="card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{{ report.vulnerabilities | length }}</div>
            </div>
            <div class="card">
                <h3>Scan Status</h3>
                <div class="value">{{ report.status }}</div>
            </div>
            <div class="card">
                <h3>URLs Tested</h3>
                <div class="value">{{ report.statistics.get('urls_processed', 0) }}</div>
            </div>
            <div class="card">
                <h3>Requests Made</h3>
                <div class="value">{{ report.statistics.get('requests_made', 0) }}</div>
            </div>
        </div>

        {% if report.executive_summary %}
        <div class="ai-insights">
            <h3>📊 Executive Summary</h3>
            <p>{{ report.executive_summary }}</p>
        </div>
        {% endif %}

        {% if report.ai_insights %}
        <div class="ai-insights">
            <h3>🤖 AI Insights</h3>
            <p><strong>Risk Level:</strong> {{ report.ai_insights.get('target_profile', {}).get('risk_level', 'Unknown') }}</p>
            <p><strong>Technologies Detected:</strong> {{ report.ai_insights.get('target_profile', {}).get('technologies', []) | join(', ') }}</p>
            <p><strong>Predicted Success Rate:</strong> {{ (report.ai_insights.get('recommendations', {}).get('predicted_success_rate', 0) * 100) | round(1) }}%</p>
        </div>
        {% endif %}

        <h2>🔍 Vulnerability Details</h2>
        {% if report.vulnerabilities %}
            {% for vuln in report.vulnerabilities %}
            <div class="vulnerability">
                <div class="vuln-header">
                    <div class="vuln-title">{{ vuln.title }}</div>
                    <div class="vuln-meta">
                        <span class="severity-{{ vuln.severity.lower() }}">{{ vuln.severity.upper() }}</span> | 
                        {{ vuln.url }} | 
                        Parameter: {{ vuln.parameter }}
                    </div>
                </div>
                <div class="vuln-body">
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    <p><strong>Impact:</strong> {{ vuln.impact }}</p>
                    
                    <h4>Payload Used:</h4>
                    <div class="code-block">{{ vuln.payload }}</div>
                    
                    <h4>Evidence:</h4>
                    <div class="code-block">{{ vuln.evidence }}</div>
                    
                    <h4>Recommendation:</h4>
                    <p>{{ vuln.recommendation }}</p>
                    
                    {% if vuln.references %}
                    <h4>References:</h4>
                    <ul>
                        {% for ref in vuln.references %}
                        <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        {% else %}
        <div class="no-vulnerabilities">
            <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
            <h3>No Vulnerabilities Found</h3>
            <p>The scan completed successfully without finding any XSS vulnerabilities.</p>
        </div>
        {% endif %}

        {% if report.recommendations %}
        <div class="recommendations">
            <h3>💡 Recommendations</h3>
            <ul>
                {% for recommendation in report.recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <div class="footer">
            <p>Generated by XSStrike v3.1.5 on {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
    </div>
</body>
</html>
        """

        html_template_path = self.template_dir / "report.html"
        if not html_template_path.exists():
            html_template_path.write_text(html_template.strip())

    def generate_report(self, scan_result: ScanResult, config: ReportConfig) -> str:
        """
        Generate a comprehensive report from scan results.
        
        Args:
            scan_result: Scan result data
            config: Report configuration
            
        Returns:
            str: Generated report content or file path
        """
        self.logger.info(f"Generating {config.output_format.upper()} report for scan {scan_result.scan_id}")

        # Create structured report data
        report = self._create_report_structure(scan_result, config)

        # Generate report based on format
        if config.output_format.lower() == "html":
            return self._generate_html_report(report, config)
        elif config.output_format.lower() == "json":
            return self._generate_json_report(report, config)
        elif config.output_format.lower() == "csv":
            return self._generate_csv_report(report, config)
        elif config.output_format.lower() == "xml":
            return self._generate_xml_report(report, config)
        else:
            raise ValueError(f"Unsupported output format: {config.output_format}")

    def _create_report_structure(self, scan_result: ScanResult, config: ReportConfig) -> ScanReport:
        """Create structured report data from scan results."""
        # Convert scan result vulnerabilities to structured format
        vulnerabilities = []
        for i, vuln in enumerate(scan_result.vulnerabilities):
            structured_vuln = VulnerabilityReport(
                id=f"XSS-{i + 1:03d}",
                title=f"Cross-Site Scripting (XSS) - {vuln.get('type', 'Reflected')}",
                severity=vuln.get('severity', 'medium'),
                risk_score=self._calculate_risk_score(vuln.get('severity', 'medium')),
                description=vuln.get('description', 'Cross-site scripting vulnerability detected'),
                url=vuln.get('url', scan_result.target or ''),
                parameter=vuln.get('parameter', 'unknown'),
                payload=vuln.get('payload', ''),
                evidence=vuln.get('evidence', ''),
                impact=self._get_impact_description(vuln.get('severity', 'medium')),
                recommendation=self._get_remediation_advice(vuln.get('type', 'reflected')),
                references=self._get_security_references(),
                cwe_id="CWE-79",
                discovered_at=vuln.get('timestamp', datetime.now().isoformat())
            )
            vulnerabilities.append(structured_vuln)

        # Create comprehensive statistics
        statistics = {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerability_breakdown': self._get_vulnerability_breakdown(vulnerabilities),
            'scan_efficiency': scan_result.metadata.get('scan_efficiency', 0),
            'urls_processed': scan_result.urls_processed,
            'requests_made': scan_result.requests_made,
            'forms_found': scan_result.forms_found,
            'cache_hit_rate': scan_result.metadata.get('cache_hit_rate', 0)
        }

        # Extract target information
        target_info = {
            'url': scan_result.target,
            'domain': urlparse(scan_result.target).netloc if scan_result.target else '',
            'technology_stack': scan_result.metadata.get('technology_stack', []),
            'waf_detected': scan_result.metadata.get('waf_detected'),
            'cms_detected': scan_result.metadata.get('cms_detected')
        }

        # Generate executive summary if requested
        executive_summary = None
        if config.executive_summary:
            executive_summary = self._generate_executive_summary(scan_result, vulnerabilities)

        # Generate recommendations
        recommendations = self._generate_recommendations(scan_result, vulnerabilities)

        return ScanReport(
            scan_id=scan_result.scan_id,
            target_url=scan_result.target or '',
            scan_type=scan_result.mode.value if scan_result.mode else 'unknown',
            started_at=datetime.fromtimestamp(scan_result.start_time).isoformat() if scan_result.start_time else '',
            completed_at=datetime.fromtimestamp(scan_result.end_time).isoformat() if scan_result.end_time else '',
            duration=scan_result.duration or 0,
            status=scan_result.status.value,
            vulnerabilities=vulnerabilities,
            statistics=statistics,
            target_info=target_info,
            scan_config=scan_result.metadata.get('scan_config', {}),
            ai_insights=scan_result.metadata.get('ai_analysis'),
            recommendations=recommendations,
            executive_summary=executive_summary
        )

    def _generate_html_report(self, report: ScanReport, config: ReportConfig) -> str:
        """Generate HTML report."""
        try:
            template = self.jinja_env.get_template("report.html")
            html_content = template.render(report=report, datetime=datetime)

            if config.output_file:
                output_path = Path(config.output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(html_content, encoding='utf-8')
                self.logger.info(f"HTML report saved to {output_path}")
                return str(output_path)
            else:
                return html_content

        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            raise

    def _generate_json_report(self, report: ScanReport, config: ReportConfig) -> str:
        """Generate JSON report."""
        try:
            report_dict = asdict(report)
            json_content = json.dumps(report_dict, indent=2, ensure_ascii=False)

            if config.output_file:
                output_path = Path(config.output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json_content, encoding='utf-8')
                self.logger.info(f"JSON report saved to {output_path}")
                return str(output_path)
            else:
                return json_content

        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            raise

    def _generate_csv_report(self, report: ScanReport, config: ReportConfig) -> str:
        """Generate CSV report."""
        try:
            output_path = Path(config.output_file) if config.output_file else Path("scan_report.csv")
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'ID', 'Title', 'Severity', 'Risk Score', 'URL', 'Parameter',
                    'Payload', 'Evidence', 'Impact', 'Recommendation', 'CWE ID', 'Discovered At'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for vuln in report.vulnerabilities:
                    writer.writerow({
                        'ID': vuln.id,
                        'Title': vuln.title,
                        'Severity': vuln.severity,
                        'Risk Score': vuln.risk_score,
                        'URL': vuln.url,
                        'Parameter': vuln.parameter,
                        'Payload': vuln.payload,
                        'Evidence': vuln.evidence[:200] + '...' if len(vuln.evidence) > 200 else vuln.evidence,
                        'Impact': vuln.impact,
                        'Recommendation': vuln.recommendation,
                        'CWE ID': vuln.cwe_id,
                        'Discovered At': vuln.discovered_at
                    })

            self.logger.info(f"CSV report saved to {output_path}")
            return str(output_path)

        except Exception as e:
            self.logger.error(f"Error generating CSV report: {e}")
            raise

    def _generate_xml_report(self, report: ScanReport, config: ReportConfig) -> str:
        """Generate XML report."""
        try:
            from xml.etree.ElementTree import Element, SubElement, tostring
            import xml.dom.minidom

            root = Element('xsstrike_report')
            root.set('version', '3.1.5')
            root.set('generated_at', datetime.now().isoformat())

            # Scan information
            scan_info = SubElement(root, 'scan_info')
            SubElement(scan_info, 'scan_id').text = report.scan_id
            SubElement(scan_info, 'target_url').text = report.target_url
            SubElement(scan_info, 'scan_type').text = report.scan_type
            SubElement(scan_info, 'started_at').text = report.started_at
            SubElement(scan_info, 'completed_at').text = report.completed_at
            SubElement(scan_info, 'duration').text = str(report.duration)
            SubElement(scan_info, 'status').text = report.status

            # Statistics
            stats = SubElement(root, 'statistics')
            for key, value in report.statistics.items():
                if isinstance(value, dict):
                    stat_elem = SubElement(stats, key)
                    for sub_key, sub_value in value.items():
                        SubElement(stat_elem, sub_key).text = str(sub_value)
                else:
                    SubElement(stats, key).text = str(value)

            # Vulnerabilities
            vulns = SubElement(root, 'vulnerabilities')
            for vuln in report.vulnerabilities:
                vuln_elem = SubElement(vulns, 'vulnerability')
                vuln_elem.set('id', vuln.id)
                vuln_elem.set('severity', vuln.severity)

                SubElement(vuln_elem, 'title').text = vuln.title
                SubElement(vuln_elem, 'description').text = vuln.description
                SubElement(vuln_elem, 'url').text = vuln.url
                SubElement(vuln_elem, 'parameter').text = vuln.parameter
                SubElement(vuln_elem, 'payload').text = vuln.payload
                SubElement(vuln_elem, 'evidence').text = vuln.evidence
                SubElement(vuln_elem, 'impact').text = vuln.impact
                SubElement(vuln_elem, 'recommendation').text = vuln.recommendation
                SubElement(vuln_elem, 'cwe_id').text = vuln.cwe_id or ''
                SubElement(vuln_elem, 'discovered_at').text = vuln.discovered_at or ''

            # Pretty print XML
            rough_string = tostring(root, 'utf-8')
            reparsed = xml.dom.minidom.parseString(rough_string)
            xml_content = reparsed.toprettyxml(indent="  ")

            if config.output_file:
                output_path = Path(config.output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(xml_content, encoding='utf-8')
                self.logger.info(f"XML report saved to {output_path}")
                return str(output_path)
            else:
                return xml_content

        except Exception as e:
            self.logger.error(f"Error generating XML report: {e}")
            raise

    def _calculate_risk_score(self, severity: str) -> float:
        """Calculate numerical risk score from severity."""
        severity_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'info': 1.0
        }
        return severity_scores.get(severity.lower(), 5.0)

    def _get_impact_description(self, severity: str) -> str:
        """Get impact description based on severity."""
        impacts = {
            'critical': 'Critical security risk. Immediate action required. Full compromise of user data and application security.',
            'high': 'High security risk. Prompt action required. Significant potential for data theft and user compromise.',
            'medium': 'Medium security risk. Should be addressed soon. Moderate potential for security compromise.',
            'low': 'Low security risk. Address when convenient. Limited potential for security impact.',
            'info': 'Informational finding. No immediate security risk but worth noting.'
        }
        return impacts.get(severity.lower(), impacts['medium'])

    def _get_remediation_advice(self, vuln_type: str) -> str:
        """Get remediation advice based on vulnerability type."""
        remediation = {
            'reflected': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.',
            'stored': 'Implement strict input validation, output encoding, and content filtering. Use CSP headers and consider WAF protection.',
            'dom': 'Avoid using dangerous DOM methods. Implement proper client-side validation and sanitization.',
            'blind': 'Implement comprehensive input validation and monitoring. Use CSP headers and security logging.'
        }
        return remediation.get(vuln_type.lower(), remediation['reflected'])

    def _get_security_references(self) -> List[str]:
        """Get security references for XSS vulnerabilities."""
        return [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]

    def _get_vulnerability_breakdown(self, vulnerabilities: List[VulnerabilityReport]) -> Dict[str, int]:
        """Get vulnerability breakdown by severity."""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown

    def _generate_executive_summary(self, scan_result: ScanResult,
                                    vulnerabilities: List[VulnerabilityReport]) -> str:
        """Generate executive summary for the report."""
        total_vulns = len(vulnerabilities)
        target_domain = urlparse(scan_result.target).netloc if scan_result.target else 'Unknown'

        if total_vulns == 0:
            return f"Security assessment of {target_domain} completed successfully with no XSS vulnerabilities identified. The application demonstrates good security practices against cross-site scripting attacks."

        severity_counts = self._get_vulnerability_breakdown(vulnerabilities)
        high_risk_count = severity_counts['critical'] + severity_counts['high']

        summary = f"Security assessment of {target_domain} identified {total_vulns} XSS vulnerabilities. "

        if high_risk_count > 0:
            summary += f"Critical attention required: {high_risk_count} high-risk vulnerabilities found that could lead to data theft, session hijacking, and unauthorized access. "

        summary += f"Immediate remediation recommended focusing on input validation, output encoding, and Content Security Policy implementation."

        return summary

    def _generate_recommendations(self, scan_result: ScanResult,
                                  vulnerabilities: List[VulnerabilityReport]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        if vulnerabilities:
            recommendations.extend([
                "Implement comprehensive input validation for all user-supplied data",
                "Apply proper output encoding/escaping based on output context (HTML, JavaScript, CSS, URL)",
                "Deploy Content Security Policy (CSP) headers to prevent XSS execution",
                "Consider implementing a Web Application Firewall (WAF) for additional protection",
                "Conduct regular security code reviews and penetration testing",
                "Implement security headers (X-XSS-Protection, X-Content-Type-Options, X-Frame-Options)"
            ])
        else:
            recommendations.extend([
                "Maintain current security practices and continue regular security assessments",
                "Consider implementing additional security headers if not already in place",
                "Keep all frameworks and libraries updated to latest secure versions",
                "Implement security monitoring and logging for suspicious activities"
            ])

        # Add AI-specific recommendations if available
        if scan_result.metadata.get('ai_analysis'):
            ai_insights = scan_result.metadata['ai_analysis']
            if 'recommendations' in ai_insights:
                recommendations.extend(ai_insights['recommendations'])

        return recommendations

    # Jinja2 filters
    def _severity_color_filter(self, severity: str) -> str:
        """Return CSS class for severity color."""
        return f"severity-{severity.lower()}"

    def _format_datetime_filter(self, timestamp: str) -> str:
        """Format datetime string."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return timestamp

    def _format_duration_filter(self, duration: float) -> str:
        """Format duration in seconds to human readable format."""
        if duration < 60:
            return f"{duration:.1f} seconds"
        elif duration < 3600:
            return f"{duration / 60:.1f} minutes"
        else:
            return f"{duration / 3600:.1f} hours"


# Global report generator instance
report_generator = ReportGenerator()
