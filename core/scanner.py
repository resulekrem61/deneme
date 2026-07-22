#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vulnerability Scanner - Ana tarama motoru
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from datetime import datetime
from loguru import logger
import re

from config.settings import Settings
from modules.discovery import SubdomainDiscovery, TechStackDetection
from modules.vulnerabilities import (
    SQLiDetector, XSSDetector, IDORDetector, LFIDetector,
    SSRFDetector, AuthBypassDetector, CORSDetector, SecurityHeadersAnalyzer,
    SSLAnalyzer, GitExposureDetector, CloudMisconfigDetector, JWTAnalyzer
)
from modules.analysis import CVSSCalculator


class VulnerabilityScanner:
    """Ana vulnerability scanner sınıfı"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Detector'ları başlat
        self.detectors = {
            'sqli': SQLiDetector(settings),
            'xss': XSSDetector(settings),
            'idor': IDORDetector(settings),
            'lfi': LFIDetector(settings),
            'ssrf': SSRFDetector(settings),
            'auth_bypass': AuthBypassDetector(settings),
            'cors': CORSDetector(settings),
            'headers': SecurityHeadersAnalyzer(settings),
            'ssl': SSLAnalyzer(settings),
            'git': GitExposureDetector(settings),
            'cloud': CloudMisconfigDetector(settings),
            'jwt': JWTAnalyzer(settings),
        }
        
        # Discovery modülleri
        self.discovery = SubdomainDiscovery(settings)
        self.tech_detector = TechStackDetection(settings)
        self.cvss_calc = CVSSCalculator()
    
    def validate_url(self, url: str) -> bool:
        """URL'yi valide et"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def is_in_scope(self, url: str) -> bool:
        """URL'nin scope içinde olup olmadığını kontrol et"""
        return self.settings.is_url_in_scope(url)
    
    async def __aenter__(self):
        """Async context manager giriş"""
        connector = aiohttp.TCPConnector(limit_per_host=5)
        self.session = aiohttp.ClientSession(connector=connector)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager çıkış"""
        if self.session:
            await self.session.close()
    
    async def scan(self, url: str, scan_type: str = "standard") -> Dict[str, Any]:
        """
        Hedefi tara
        
        Args:
            url: Hedef URL
            scan_type: Tarama türü (quick, standard, full, aggressive)
        
        Returns:
            Tarama sonuçları
        """
        async with self:
            results = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'scan_type': scan_type,
                'vulnerabilities': [],
                'discovery': {},
                'tech_stack': [],
                'summary': {}
            }
            
            try:
                # 1. Discovery (Subdomain keşfi)
                if scan_type in ['standard', 'full', 'aggressive']:
                    logger.info("🔍 Subdomain keşfi başlanıyor...")
                    subdomains = await self.discovery.discover(urlparse(url).netloc)
                    results['discovery']['subdomains'] = subdomains
                
                # 2. Tech Stack Tespiti
                if scan_type in ['standard', 'full', 'aggressive']:
                    logger.info("🛠️ Tech stack tespiti başlanıyor...")
                    tech_stack = await self.tech_detector.detect(url)
                    results['tech_stack'] = tech_stack
                
                # 3. Vulnerability Scanning
                logger.info("🐛 Zafiyet taraması başlanıyor...")
                
                if scan_type == 'quick':
                    vulns = await self._quick_scan(url)
                elif scan_type == 'standard':
                    vulns = await self._standard_scan(url)
                elif scan_type == 'full':
                    vulns = await self._full_scan(url)
                else:  # aggressive
                    vulns = await self._aggressive_scan(url)
                
                results['vulnerabilities'] = vulns
                
                # CVSS hesapla
                for vuln in results['vulnerabilities']:
                    vuln['cvss'] = self.cvss_calc.calculate(vuln)
                
                # Özet
                results['summary'] = self._generate_summary(results)
                
            except Exception as e:
                logger.error(f"❌ Tarama hatası: {str(e)}")
                results['error'] = str(e)
            
            return results
    
    async def _quick_scan(self, url: str) -> List[Dict]:
        """Hızlı tarama"""
        vulnerabilities = []
        
        if self.settings.scanner.check_headers:
            vulns = await self.detectors['headers'].scan(url)
            vulnerabilities.extend(vulns)
        
        if self.settings.scanner.check_ssl:
            vulns = await self.detectors['ssl'].scan(url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _standard_scan(self, url: str) -> List[Dict]:
        """Standart tarama"""
        vulnerabilities = []
        
        checks = [
            ('headers', self.detectors['headers']),
            ('ssl', self.detectors['ssl']),
            ('cors', self.detectors['cors']),
            ('git', self.detectors['git']),
        ]
        
        for name, detector in checks:
            if getattr(self.settings.scanner, f'check_{name}', True):
                try:
                    vulns = await detector.scan(url)
                    vulnerabilities.extend(vulns)
                except Exception as e:
                    logger.error(f"❌ {name} tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _full_scan(self, url: str) -> List[Dict]:
        """Tam tarama"""
        vulnerabilities = []
        
        checks = [
            ('sqli', self.detectors['sqli']),
            ('xss', self.detectors['xss']),
            ('idor', self.detectors['idor']),
            ('lfi', self.detectors['lfi']),
            ('ssrf', self.detectors['ssrf']),
            ('auth_bypass', self.detectors['auth_bypass']),
            ('cors', self.detectors['cors']),
            ('headers', self.detectors['headers']),
            ('ssl', self.detectors['ssl']),
            ('git', self.detectors['git']),
            ('cloud', self.detectors['cloud']),
            ('jwt', self.detectors['jwt']),
        ]
        
        for name, detector in checks:
            try:
                vulns = await detector.scan(url)
                vulnerabilities.extend(vulns)
            except Exception as e:
                logger.error(f"❌ {name} tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _aggressive_scan(self, url: str) -> List[Dict]:
        """Agresif tarama (Full + Directory brute-force vb.)"""
        vulnerabilities = await self._full_scan(url)
        
        # Directory brute-force eklenebilir
        
        return vulnerabilities
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Tarama özeti oluştur"""
        vulns = results['vulnerabilities']
        
        # CVSS seviyelerine göre say
        critical = sum(1 for v in vulns if v.get('cvss_score', 0) >= 9.0)
        high = sum(1 for v in vulns if 7.0 <= v.get('cvss_score', 0) < 9.0)
        medium = sum(1 for v in vulns if 4.0 <= v.get('cvss_score', 0) < 7.0)
        low = sum(1 for v in vulns if 0.1 <= v.get('cvss_score', 0) < 4.0)
        info = sum(1 for v in vulns if v.get('cvss_score', 0) == 0)
        
        return {
            'total': len(vulns),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info,
        }
