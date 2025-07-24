"""
Report Generation Module for ShadowX
Generates comprehensive HTML and text reports
"""

import os
import time
import json
from datetime import datetime
import base64

class ReportGenerator:
    def __init__(self, output_dir="./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_reports(self, vulnerabilities, scan_info=None):
        """Generate both HTML and text reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate HTML report
        html_filename = f"shadowx_report_{timestamp}.html"
        html_filepath = os.path.join(self.output_dir, html_filename)
        self._generate_html_report(vulnerabilities, html_filepath, scan_info)
        
        # Generate text report
        txt_filename = f"shadowx_report_{timestamp}.txt"
        txt_filepath = os.path.join(self.output_dir, txt_filename)
        self._generate_text_report(vulnerabilities, txt_filepath, scan_info)
        
        # Generate JSON report
        json_filename = f"shadowx_report_{timestamp}.json"
        json_filepath = os.path.join(self.output_dir, json_filename)
        self._generate_json_report(vulnerabilities, json_filepath, scan_info)
        
        return html_filepath, txt_filepath
        
    def _generate_html_report(self, vulnerabilities, filepath, scan_info):
        """Generate detailed HTML report"""
        total_vulns = len(vulnerabilities)
        unique_urls = len(set(v['url'] for v in vulnerabilities))
        
        # Calculate vulnerability statistics
        vuln_stats = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_stats[vuln_type] = vuln_stats.get(vuln_type, 0) + 1
            
        # Generate vulnerability cards
        vulnerability_cards = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            evidence_html = self._format_evidence_html(vuln.get('evidence', {}))
            screenshot_html = self._format_screenshot_html(vuln.get('screenshot'))
            
            severity_class = self._get_severity_class(vuln.get('type', ''))
            
            vulnerability_cards += f"""
            <div class="vulnerability-card {severity_class}">
                <div class="vuln-header">
                    <h3>#{i} {vuln.get('type', 'Unknown XSS')}</h3>
                    <span class="severity-badge {severity_class}">{self._get_severity_label(vuln.get('type', ''))}</span>
                </div>
                
                <div class="vuln-details">
                    <div class="detail-row">
                        <span class="label">URL:</span>
                        <span class="value">{vuln.get('url', 'N/A')}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="label">Injection Point:</span>
                        <span class="value">{vuln.get('injection_point', 'N/A')}</span>
                    </div>
                    
                    {f'<div class="detail-row"><span class="label">Parameter:</span><span class="value">{vuln.get("parameter", "N/A")}</span></div>' if vuln.get('parameter') else ''}
                    
                    <div class="detail-row">
                        <span class="label">Timestamp:</span>
                        <span class="value">{vuln.get('timestamp', 'N/A')}</span>
                    </div>
                </div>
                
                <div class="payload-section">
                    <h4>Payload</h4>
                    <div class="payload-code">{self._escape_html(vuln.get('payload', 'N/A'))}</div>
                </div>
                
                {evidence_html}
                {screenshot_html}
                
                <div class="vuln-flags">
                    <span class="flag {'active' if vuln.get('reflected') else 'inactive'}">Reflected</span>
                    <span class="flag {'active' if vuln.get('javascript_executed') else 'inactive'}">JS Executed</span>
                    <span class="flag {'active' if vuln.get('dom_modified') else 'inactive'}">DOM Modified</span>
                </div>
            </div>
            """
            
        # Generate statistics charts data
        stats_json = json.dumps(list(vuln_stats.items()))
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowX Security Scan Report - {scan_info.get('author', 'adce626') if scan_info else 'adce626'}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {{
            --primary-color: #ff6b6b;
            --secondary-color: #4ecdc4;
            --accent-color: #45b7d1;
            --background-dark: #0f0f23;
            --background-card: #1a1a2e;
            --text-primary: #ffffff;
            --text-secondary: #b8b8b8;
            --border-color: #333366;
            --success-color: #00d084;
            --warning-color: #ffb347;
            --danger-color: #ff6b6b;
            --code-bg: #16213e;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', sans-serif;
            background: var(--background-dark);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 107, 107, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(78, 205, 196, 0.3) 0%, transparent 50%);
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--background-card), rgba(26, 26, 46, 0.8));
            border-radius: 20px;
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color), var(--accent-color));
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            font-size: 1.2rem;
            color: var(--text-secondary);
            margin-bottom: 20px;
        }}
        
        .header .author {{
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-color);
            font-weight: 500;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: var(--background-card);
            padding: 30px;
            border-radius: 15px;
            border: 1px solid var(--border-color);
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
            display: block;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .vulnerabilities-section {{
            margin-top: 40px;
        }}
        
        .section-title {{
            font-size: 1.8rem;
            margin-bottom: 30px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title::before {{
            content: '';
            width: 4px;
            height: 30px;
            background: linear-gradient(180deg, var(--primary-color), var(--secondary-color));
            border-radius: 2px;
        }}
        
        .vulnerability-card {{
            background: var(--background-card);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }}
        
        .vulnerability-card.high::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--danger-color);
        }}
        
        .vulnerability-card.medium::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--warning-color);
        }}
        
        .vulnerability-card.low::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--success-color);
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}
        
        .vuln-header h3 {{
            color: var(--text-primary);
            font-size: 1.3rem;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .severity-badge.high {{
            background: rgba(255, 107, 107, 0.2);
            color: var(--danger-color);
            border: 1px solid var(--danger-color);
        }}
        
        .severity-badge.medium {{
            background: rgba(255, 179, 71, 0.2);
            color: var(--warning-color);
            border: 1px solid var(--warning-color);
        }}
        
        .severity-badge.low {{
            background: rgba(0, 208, 132, 0.2);
            color: var(--success-color);
            border: 1px solid var(--success-color);
        }}
        
        .vuln-details {{
            margin-bottom: 20px;
        }}
        
        .detail-row {{
            display: flex;
            margin-bottom: 10px;
            align-items: flex-start;
        }}
        
        .detail-row .label {{
            min-width: 120px;
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .detail-row .value {{
            color: var(--text-primary);
            word-break: break-all;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }}
        
        .payload-section {{
            margin: 20px 0;
        }}
        
        .payload-section h4 {{
            color: var(--text-primary);
            margin-bottom: 10px;
            font-size: 1.1rem;
        }}
        
        .payload-code {{
            background: var(--code-bg);
            padding: 15px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: #61dafb;
            border: 1px solid var(--border-color);
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .evidence-section {{
            margin: 20px 0;
            padding: 20px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }}
        
        .evidence-section h4 {{
            color: var(--secondary-color);
            margin-bottom: 15px;
            font-size: 1.1rem;
        }}
        
        .evidence-item {{
            margin-bottom: 10px;
            padding: 10px;
            background: var(--code-bg);
            border-radius: 5px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        
        .screenshot-section {{
            margin: 20px 0;
        }}
        
        .screenshot-section h4 {{
            color: var(--text-primary);
            margin-bottom: 10px;
        }}
        
        .screenshot-section img {{
            max-width: 100%;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        
        .vuln-flags {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 20px;
        }}
        
        .flag {{
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        
        .flag.active {{
            background: rgba(0, 208, 132, 0.2);
            color: var(--success-color);
            border: 1px solid var(--success-color);
        }}
        
        .flag.inactive {{
            background: rgba(184, 184, 184, 0.1);
            color: var(--text-secondary);
            border: 1px solid var(--text-secondary);
        }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding: 30px;
            background: var(--background-card);
            border-radius: 15px;
            border: 1px solid var(--border-color);
        }}
        
        .footer p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .footer .tool-info {{
            color: var(--accent-color);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .vuln-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }}
            
            .detail-row {{
                flex-direction: column;
                gap: 5px;
            }}
            
            .detail-row .label {{
                min-width: auto;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ShadowX Security Report</h1>
            <div class="subtitle">Advanced XSS Vulnerability Assessment</div>
            <div class="author">Created by: {scan_info.get('author', 'adce626') if scan_info else 'adce626'}</div>
            <div class="author">Generated: {scan_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')) if scan_info else datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-number">{total_vulns}</span>
                <span class="stat-label">Total Vulnerabilities</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{unique_urls}</span>
                <span class="stat-label">Affected URLs</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{len(vuln_stats)}</span>
                <span class="stat-label">Vulnerability Types</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{scan_info.get('version', '1.0') if scan_info else '1.0'}</span>
                <span class="stat-label">Scanner Version</span>
            </div>
        </div>
        
        <div class="vulnerabilities-section">
            <h2 class="section-title">Discovered Vulnerabilities</h2>
            {vulnerability_cards if vulnerability_cards else '<div class="vulnerability-card"><p>No vulnerabilities found.</p></div>'}
        </div>
        
        <div class="footer">
            <p class="tool-info">ShadowX v{scan_info.get('version', '1.0') if scan_info else '1.0'} - Advanced XSS Vulnerability Scanner</p>
            <p>Report generated by {scan_info.get('author', 'adce626') if scan_info else 'adce626'} on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
    def _generate_text_report(self, vulnerabilities, filepath, scan_info):
        """Generate plain text report"""
        total_vulns = len(vulnerabilities)
        unique_urls = len(set(v['url'] for v in vulnerabilities))
        
        # Calculate vulnerability statistics
        vuln_stats = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_stats[vuln_type] = vuln_stats.get(vuln_type, 0) + 1
            
        content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                            SHADOWX SECURITY REPORT                          ║
║                        Advanced XSS Vulnerability Scanner                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Created by: {scan_info.get('author', 'adce626') if scan_info else 'adce626':<62} ║
║ Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<62} ║
║ Version:    {scan_info.get('version', '1.0') if scan_info else '1.0':<62} ║
╚══════════════════════════════════════════════════════════════════════════════╝

SCAN SUMMARY
═══════════════════════════════════════════════════════════════════════════════
• Total Vulnerabilities Found: {total_vulns}
• Unique URLs Affected: {unique_urls}
• Vulnerability Types: {len(vuln_stats)}

VULNERABILITY BREAKDOWN
═══════════════════════════════════════════════════════════════════════════════
"""
        
        for vuln_type, count in sorted(vuln_stats.items()):
            content += f"• {vuln_type}: {count}\n"
            
        content += "\n\nDETAILED FINDINGS\n"
        content += "═" * 79 + "\n\n"
        
        for i, vuln in enumerate(vulnerabilities, 1):
            content += f"[{i}] {vuln.get('type', 'Unknown XSS')}\n"
            content += "─" * 79 + "\n"
            content += f"URL:              {vuln.get('url', 'N/A')}\n"
            content += f"Injection Point:  {vuln.get('injection_point', 'N/A')}\n"
            
            if vuln.get('parameter'):
                content += f"Parameter:        {vuln.get('parameter')}\n"
                
            content += f"Timestamp:        {vuln.get('timestamp', 'N/A')}\n"
            content += f"Reflected:        {'Yes' if vuln.get('reflected') else 'No'}\n"
            content += f"JS Executed:      {'Yes' if vuln.get('javascript_executed') else 'No'}\n"
            content += f"DOM Modified:     {'Yes' if vuln.get('dom_modified') else 'No'}\n"
            
            content += f"\nPayload:\n{vuln.get('payload', 'N/A')}\n"
            
            evidence = vuln.get('evidence', {})
            if evidence.get('javascript'):
                content += f"\nJavaScript Evidence:\n{evidence['javascript']}\n"
            if evidence.get('dom'):
                content += f"\nDOM Evidence:\n{evidence['dom']}\n"
                
            if vuln.get('screenshot'):
                content += f"\nScreenshot: {vuln.get('screenshot')}\n"
                
            content += "\n" + "=" * 79 + "\n\n"
            
        content += f"""
REPORT FOOTER
═══════════════════════════════════════════════════════════════════════════════
This report was generated by ShadowX v{scan_info.get('version', '1.0') if scan_info else '1.0'}
Advanced XSS Vulnerability Scanner created by {scan_info.get('author', 'adce626') if scan_info else 'adce626'}

For questions or support, please refer to the ShadowX documentation.
Report generated on: {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
    def _generate_json_report(self, vulnerabilities, filepath, scan_info):
        """Generate JSON report for programmatic analysis"""
        report_data = {
            'scan_info': {
                'tool_name': 'ShadowX',
                'version': scan_info.get('version', '1.0') if scan_info else '1.0',
                'author': scan_info.get('author', 'adce626') if scan_info else 'adce626',
                'timestamp': scan_info.get('timestamp', datetime.now().isoformat()) if scan_info else datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'unique_urls': len(set(v['url'] for v in vulnerabilities))
            },
            'vulnerabilities': vulnerabilities,
            'statistics': self._calculate_statistics(vulnerabilities)
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
    def _calculate_statistics(self, vulnerabilities):
        """Calculate vulnerability statistics"""
        stats = {
            'by_type': {},
            'by_injection_point': {},
            'by_url': {},
            'execution_stats': {
                'reflected': 0,
                'javascript_executed': 0,
                'dom_modified': 0
            }
        }
        
        for vuln in vulnerabilities:
            # By type
            vuln_type = vuln.get('type', 'Unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # By injection point
            injection_point = vuln.get('injection_point', 'Unknown')
            stats['by_injection_point'][injection_point] = stats['by_injection_point'].get(injection_point, 0) + 1
            
            # By URL
            url = vuln.get('url', 'Unknown')
            stats['by_url'][url] = stats['by_url'].get(url, 0) + 1
            
            # Execution stats
            if vuln.get('reflected'):
                stats['execution_stats']['reflected'] += 1
            if vuln.get('javascript_executed'):
                stats['execution_stats']['javascript_executed'] += 1
            if vuln.get('dom_modified'):
                stats['execution_stats']['dom_modified'] += 1
                
        return stats
        
    def _format_evidence_html(self, evidence):
        """Format evidence for HTML display"""
        if not evidence or not any(evidence.values()):
            return ""
            
        evidence_html = '<div class="evidence-section"><h4>Evidence</h4>'
        
        if evidence.get('javascript'):
            evidence_html += f'<div class="evidence-item"><strong>JavaScript:</strong> {self._escape_html(str(evidence["javascript"]))}</div>'
            
        if evidence.get('dom'):
            evidence_html += f'<div class="evidence-item"><strong>DOM:</strong> {self._escape_html(str(evidence["dom"]))}</div>'
            
        evidence_html += '</div>'
        return evidence_html
        
    def _format_screenshot_html(self, screenshot_path):
        """Format screenshot for HTML display"""
        if not screenshot_path or not os.path.exists(screenshot_path):
            return ""
            
        try:
            with open(screenshot_path, 'rb') as f:
                screenshot_data = base64.b64encode(f.read()).decode('utf-8')
                
            return f'''
            <div class="screenshot-section">
                <h4>Screenshot</h4>
                <img src="data:image/png;base64,{screenshot_data}" alt="XSS Screenshot" />
            </div>
            '''
        except Exception:
            return f'<div class="screenshot-section"><h4>Screenshot</h4><p>Screenshot available at: {screenshot_path}</p></div>'
            
    def _get_severity_class(self, vuln_type):
        """Get CSS class based on vulnerability type"""
        if 'Stored' in vuln_type or 'DOM' in vuln_type:
            return 'high'
        elif 'Reflected' in vuln_type:
            return 'medium'
        elif 'Blind' in vuln_type:
            return 'high'
        else:
            return 'low'
            
    def _get_severity_label(self, vuln_type):
        """Get severity label based on vulnerability type"""
        if 'Stored' in vuln_type or 'DOM' in vuln_type:
            return 'High'
        elif 'Reflected' in vuln_type:
            return 'Medium'
        elif 'Blind' in vuln_type:
            return 'High'
        else:
            return 'Low'
            
    def _escape_html(self, text):
        """Escape HTML characters"""
        if not text:
            return ""
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
