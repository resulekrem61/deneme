#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rapor oluşturma motoru
"""

import json
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger
import csv
import xml.etree.ElementTree as ET
from jinja2 import Template

from config.settings import Settings
from modules.analysis import CVSSCalculator, BountyEstimator


class ReportGenerator:
    """Rapor oluşturma sınıfı"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.cvss_calc = CVSSCalculator()
        self.bounty_est = BountyEstimator()
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Rapor şablonlarını yükle"""
        return {
            'hackerone': self._get_hackerone_template(),
            'bugcrowd': self._get_bugcrowd_template(),
            'intigriti': self._get_intigriti_template(),
            'standard': self._get_standard_template(),
        }
    
    async def generate(self, results: Dict[str, Any], format_type: str = "standard") -> str:
        """
        Rapor oluştur
        
        Args:
            results: Tarama sonuçları
            format_type: Rapor formatı (hackerone, bugcrowd, intigriti, standard)
        
        Returns:
            Rapor içeriği
        """
        try:
            if format_type == 'json':
                return self._generate_json(results)
            elif format_type == 'csv':
                return self._generate_csv(results)
            elif format_type == 'xml':
                return self._generate_xml(results)
            elif format_type == 'html':
                return self._generate_html(results)
            elif format_type in self.templates:
                return self._generate_from_template(results, format_type)
            else:
                return self._generate_json(results)
        
        except Exception as e:
            logger.error(f"❌ Rapor oluşturma hatası: {str(e)}")
            return ""
    
    def _generate_json(self, results: Dict) -> str:
        """JSON rapor oluştur"""
        return json.dumps(results, indent=2, ensure_ascii=False)
    
    def _generate_csv(self, results: Dict) -> str:
        """CSV rapor oluştur"""
        vulns = results.get('vulnerabilities', [])
        
        if not vulns:
            return "No vulnerabilities found"
        
        # CSV başlığı
        headers = ['ID', 'Type', 'Severity', 'CVSS Score', 'URL', 'Description', 'Recommendation']
        
        lines = [','.join(headers)]
        for i, vuln in enumerate(vulns, 1):
            row = [
                str(i),
                vuln.get('type', 'Unknown'),
                vuln.get('cvss', {}).get('severity', 'Unknown'),
                str(vuln.get('cvss', {}).get('score', 0)),
                vuln.get('url', ''),
                vuln.get('description', ''),
                vuln.get('recommendation', ''),
            ]
            lines.append(','.join(f'"{field}"' for field in row))
        
        return '\n'.join(lines)
    
    def _generate_xml(self, results: Dict) -> str:
        """XML rapor oluştur"""
        root = ET.Element('scan_report')
        
        # Metadata
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'url').text = results.get('url', '')
        ET.SubElement(metadata, 'timestamp').text = results.get('timestamp', '')
        ET.SubElement(metadata, 'scan_type').text = results.get('scan_type', '')
        
        # Summary
        summary = ET.SubElement(root, 'summary')
        for key, val in results.get('summary', {}).items():
            ET.SubElement(summary, key).text = str(val)
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'vulnerabilities')
        for vuln in results.get('vulnerabilities', []):
            vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
            for key, val in vuln.items():
                if isinstance(val, dict):
                    sub_elem = ET.SubElement(vuln_elem, key)
                    for k, v in val.items():
                        ET.SubElement(sub_elem, k).text = str(v)
                else:
                    ET.SubElement(vuln_elem, key).text = str(val)
        
        return ET.tostring(root, encoding='unicode')
    
    def _generate_html(self, results: Dict) -> str:
        """HTML rapor oluştur"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Kartavçı - Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #333; color: white; padding: 20px; border-radius: 5px; }
                .summary { background: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px; }
                .vulnerability { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
                .critical { border-left: 5px solid #d32f2f; }
                .high { border-left: 5px solid #f57c00; }
                .medium { border-left: 5px solid #fbc02d; }
                .low { border-left: 5px solid #388e3c; }
                .info { border-left: 5px solid #1976d2; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f5f5f5; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 Kartavçı - Scan Report</h1>
                <p>Target: {{ url }}</p>
                <p>Scan Date: {{ timestamp }}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <table>
                    <tr>
                        <th>Total</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Info</th>
                    </tr>
                    <tr>
                        <td>{{ summary.total }}</td>
                        <td>{{ summary.critical }}</td>
                        <td>{{ summary.high }}</td>
                        <td>{{ summary.medium }}</td>
                        <td>{{ summary.low }}</td>
                        <td>{{ summary.info }}</td>
                    </tr>
                </table>
            </div>
            
            <div class="vulnerabilities">
                <h2>Vulnerabilities</h2>
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.cvss.severity.lower() }}">
                    <h3>{{ vuln.type }} (CVSS: {{ vuln.cvss.score }})</h3>
                    <p><strong>URL:</strong> {{ vuln.url }}</p>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    <p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        return template.render(
            url=results.get('url', ''),
            timestamp=results.get('timestamp', ''),
            summary=results.get('summary', {}),
            vulnerabilities=results.get('vulnerabilities', [])
        )
    
    def _generate_from_template(self, results: Dict, format_type: str) -> str:
        """Template kullanarak rapor oluştur"""
        template_str = self.templates.get(format_type, self.templates['standard'])
        template = Template(template_str)
        return template.render(results=results)
    
    def _get_hackerone_template(self) -> str:
        """HackerOne rapor şablonu"""
        return """
# HackerOne Vulnerability Report

## Summary
{{ results.url }} - {{ results.timestamp }}

## Vulnerabilities Found: {{ results.summary.total }}

{% for vuln in results.vulnerabilities %}
### {{ vuln.type }} (CVSS: {{ vuln.cvss.score }})

**Severity:** {{ vuln.cvss.severity }}

**URL:** `{{ vuln.url }}`

**Description:**
{{ vuln.description }}

**Proof of Concept:**
```
{{ vuln.poc }}
```

**Impact:**
{{ vuln.impact }}

**Recommendation:**
{{ vuln.recommendation }}

**References:**
- CWE: {{ vuln.cwe }}
- CVSS Vector: {{ vuln.cvss_vector }}

---

{% endfor %}
"""
    
    def _get_bugcrowd_template(self) -> str:
        """Bugcrowd rapor şablonu"""
        return self._get_hackerone_template()  # Benzer format
    
    def _get_intigriti_template(self) -> str:
        """Intigriti rapor şablonu"""
        return self._get_hackerone_template()  # Benzer format
    
    def _get_standard_template(self) -> str:
        """Standart rapor şablonu"""
        return self._get_hackerone_template()
