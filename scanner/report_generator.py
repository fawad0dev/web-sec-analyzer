#!/usr/bin/env python3
"""
HTML report generation module
"""
import logging
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from string import Template

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generator for professional HTML security reports"""
    
    HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .summary-card .number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .summary-card .label {
            font-size: 1.1em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .high { color: #e74c3c; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        .info { color: #95a5a6; }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .section-title {
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            color: #2c3e50;
        }
        
        .vulnerability {
            border-left: 4px solid #e74c3c;
            padding: 20px;
            margin-bottom: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .vulnerability.medium {
            border-left-color: #f39c12;
        }
        
        .vulnerability.low {
            border-left-color: #3498db;
        }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vulnerability-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        
        .severity-badge.high {
            background: #e74c3c;
            color: white;
        }
        
        .severity-badge.medium {
            background: #f39c12;
            color: white;
        }
        
        .severity-badge.low {
            background: #3498db;
            color: white;
        }
        
        .vulnerability-detail {
            margin-bottom: 10px;
        }
        
        .vulnerability-detail strong {
            display: inline-block;
            min-width: 120px;
            color: #555;
        }
        
        .code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .info-box {
            background: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }
        
        .recommendation {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }
        
        .scan-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .scan-info div {
            margin-bottom: 5px;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
        }
        
        .no-vulnerabilities::before {
            content: "✓";
            display: block;
            font-size: 4em;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Web Security Analysis Report</h1>
            <div class="subtitle">Comprehensive Vulnerability Assessment</div>
        </div>
        
        <div class="scan-info">
            <div><strong>Target URL:</strong> $target_url</div>
            <div><strong>Scan Date:</strong> $scan_date</div>
            <div><strong>Scan Duration:</strong> $scan_duration</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="number high">$high_count</div>
                <div class="label">High Severity</div>
            </div>
            <div class="summary-card">
                <div class="number medium">$medium_count</div>
                <div class="label">Medium Severity</div>
            </div>
            <div class="summary-card">
                <div class="number low">$low_count</div>
                <div class="label">Low Severity</div>
            </div>
            <div class="summary-card">
                <div class="number info">$total_count</div>
                <div class="label">Total Issues</div>
            </div>
        </div>
        
        $sql_injection_section
        
        $xss_section
        
        $security_headers_section
        
        <div class="footer">
            <p>Generated by Web Security Analyzer v1.0.0</p>
            <p>This report is for security testing purposes only.</p>
        </div>
    </div>
</body>
</html>
""")
    
    def __init__(self):
        """Initialize report generator"""
        pass
    
    def generate_report(
        self,
        target_url: str,
        sql_vulnerabilities: List[Dict],
        xss_vulnerabilities: List[Dict],
        security_headers_findings: List[Dict],
        scan_duration: str,
        output_path: str = "security_report.html"
    ) -> str:
        """
        Generate HTML security report
        
        Args:
            target_url: Scanned URL
            sql_vulnerabilities: SQL injection findings
            xss_vulnerabilities: XSS findings
            security_headers_findings: Security headers findings
            scan_duration: Scan duration string
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        logger.info(f"Generating HTML report: {output_path}")
        
        # Calculate statistics
        high_count = 0
        medium_count = 0
        low_count = 0
        
        all_findings = sql_vulnerabilities + xss_vulnerabilities + security_headers_findings
        
        for finding in all_findings:
            severity = finding.get('severity', '').lower()
            if severity == 'high':
                high_count += 1
            elif severity == 'medium':
                medium_count += 1
            elif severity == 'low':
                low_count += 1
        
        total_count = len(all_findings)
        
        # Generate sections
        sql_section = self._generate_section(
            "SQL Injection Vulnerabilities",
            sql_vulnerabilities,
            "No SQL injection vulnerabilities detected."
        )
        
        xss_section = self._generate_section(
            "Cross-Site Scripting (XSS) Vulnerabilities",
            xss_vulnerabilities,
            "No XSS vulnerabilities detected."
        )
        
        headers_section = self._generate_section(
            "Security Headers Analysis",
            security_headers_findings,
            "All recommended security headers are properly configured."
        )
        
        # Fill template
        html_content = self.HTML_TEMPLATE.substitute(
            target_url=self._escape_html(target_url),
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_duration=self._escape_html(scan_duration),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_count=total_count,
            sql_injection_section=sql_section,
            xss_section=xss_section,
            security_headers_section=headers_section
        )
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html_content, encoding='utf-8')
        
        logger.info(f"Report generated successfully: {output_path}")
        return str(output_file.absolute())
    
    def _generate_section(self, title: str, findings: List[Dict], empty_message: str) -> str:
        """
        Generate HTML section for vulnerability type
        
        Args:
            title: Section title
            findings: List of findings
            empty_message: Message to show when no findings
            
        Returns:
            HTML section string
        """
        if not findings:
            return f"""
        <div class="section">
            <h2 class="section-title">{title}</h2>
            <div class="no-vulnerabilities">{empty_message}</div>
        </div>
"""
        
        vulnerabilities_html = ""
        for finding in findings:
            vulnerabilities_html += self._generate_vulnerability_card(finding)
        
        return f"""
        <div class="section">
            <h2 class="section-title">{title}</h2>
            {vulnerabilities_html}
        </div>
"""
    
    def _generate_vulnerability_card(self, finding: Dict) -> str:
        """
        Generate HTML card for a single vulnerability
        
        Args:
            finding: Vulnerability details
            
        Returns:
            HTML card string
        """
        severity = finding.get('severity', 'Low').lower()
        vuln_type = finding.get('type', 'Unknown')
        description = finding.get('description', '')
        url = finding.get('url', '')
        parameter = finding.get('parameter', '')
        method = finding.get('method', '')
        payload = finding.get('payload', '')
        evidence = finding.get('evidence', '')
        recommendation = finding.get('recommendation', '')
        header = finding.get('header', '')
        value = finding.get('value', '')
        
        details = ""
        
        if url:
            details += f'<div class="vulnerability-detail"><strong>URL:</strong> {self._escape_html(url)}</div>'
        
        if parameter:
            details += f'<div class="vulnerability-detail"><strong>Parameter:</strong> {self._escape_html(parameter)}</div>'
        
        if method:
            details += f'<div class="vulnerability-detail"><strong>Method:</strong> {method}</div>'
        
        if header:
            details += f'<div class="vulnerability-detail"><strong>Header:</strong> {header}</div>'
        
        if value:
            details += f'<div class="vulnerability-detail"><strong>Value:</strong> {self._escape_html(value)}</div>'
        
        if payload:
            details += f'<div class="vulnerability-detail"><strong>Payload:</strong></div>'
            details += f'<div class="code">{self._escape_html(payload)}</div>'
        
        if evidence:
            details += f'<div class="info-box"><strong>Evidence:</strong><br>{self._escape_html(evidence)}</div>'
        
        if recommendation:
            details += f'<div class="recommendation"><strong>Recommendation:</strong><br>{self._escape_html(recommendation)}</div>'
        
        return f"""
            <div class="vulnerability {severity}">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{self._escape_html(vuln_type)}</div>
                    <div class="severity-badge {severity}">{severity}</div>
                </div>
                <div class="vulnerability-detail"><strong>Description:</strong> {self._escape_html(description)}</div>
                {details}
            </div>
"""
    
    def _escape_html(self, text: str) -> str:
        """
        Escape HTML special characters
        
        Args:
            text: Text to escape
            
        Returns:
            Escaped text
        """
        if not text:
            return ""
        
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
