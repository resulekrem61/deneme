#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Detector - DOM-based, Stored, Mutated
"""

from typing import List, Dict, Any
from loguru import logger
import re

from .base import BaseDetector


class AdvancedXSSDetector(BaseDetector):
    """Advanced XSS Zafiyeti Tespiti"""
    
    # DOM-based XSS sources
    DOM_SOURCES = [
        'document.location',
        'document.URL',
        'document.referrer',
        'window.location',
        'location.hash',
        'location.search',
    ]
    
    # DOM-based XSS sinks
    DOM_SINKS = [
        'innerHTML',
        'outerHTML',
        'appendChild',
        'insertBefore',
        'eval',
        'Function()',
    ]
    
    # Mutated XSS payloads
    MUTATED_PAYLOADS = [
        '<svg><style><img src="</style><img src=x onerror=alert(1)>">',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        '<TABLE><TD BACKGROUND="javascript:alert(1)">',
        '<IMG """"><SCRIPT>alert("XSS")</SCRIPT>">',
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Advanced XSS taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan advanced XSS zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Advanced XSS taraması başlanıyor: {url}")
        
        try:
            # DOM-based XSS testi
            dom_based = await self._test_dom_based_xss(url)
            if dom_based:
                vulnerabilities.extend(dom_based)
            
            # Mutated XSS testi
            mutated = await self._test_mutated_xss(url)
            if mutated:
                vulnerabilities.extend(mutated)
            
            # CSP bypass testi
            csp_bypass = await self._test_csp_bypass(url)
            if csp_bypass:
                vulnerabilities.append(csp_bypass)
        
        except Exception as e:
            logger.debug(f"❌ Advanced XSS tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_dom_based_xss(self, url: str) -> List[Dict[str, Any]]:
        """DOM-based XSS testi"""
        vulnerabilities = []
        
        response = await self._get(url)
        if not response:
            return vulnerabilities
        
        # Source ve sink'leri ara
        has_source = any(source in response for source in self.DOM_SOURCES)
        has_sink = any(sink in response for sink in self.DOM_SINKS)
        
        if has_source and has_sink:
            vuln = self._create_vulnerability(
                type_='DOM-based XSS',
                severity='High',
                url=url,
                description='DOM source ve sink kombinasyonu bulunan XSS',
                recommendation='DOM manipulasyonunda textContent veya innerText kullan',
                poc='location.hash payloadı',
                cwe='CWE-79',
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_mutated_xss(self, url: str) -> List[Dict[str, Any]]:
        """Mutated XSS testi"""
        vulnerabilities = []
        
        for payload in self.MUTATED_PAYLOADS:
            test_url = f"{url}?payload={payload}"
            response = await self._get(test_url)
            
            if response and payload in response:
                vuln = self._create_vulnerability(
                    type_='Mutated XSS',
                    severity='Medium',
                    url=url,
                    description='HTML5 parsing kurallarını bypass eden XSS',
                    recommendation='Strict Content Security Policy ekle',
                    poc=payload,
                    cwe='CWE-79',
                    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_csp_bypass(self, url: str) -> Dict[str, Any] or None:
        """CSP bypass testi"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    csp_header = resp.headers.get('Content-Security-Policy')
                    
                    if csp_header:
                        # unsafe-eval kontrolü
                        if 'unsafe-eval' in csp_header:
                            return self._create_vulnerability(
                                type_='CSP Bypass (unsafe-eval)',
                                severity='Medium',
                                url=url,
                                description='unsafe-eval bulundu - eval() bypass mümkün',
                                recommendation='unsafe-eval'i kaldır',
                                poc='Script tag üzerinden eval() çalıştır',
                                cwe='CWE-1021',
                            )
                        
                        # nonce extraction
                        if "nonce='" in csp_header or 'nonce="' in csp_header:
                            return self._create_vulnerability(
                                type_='CSP Nonce Exposure',
                                severity='High',
                                url=url,
                                description='CSP nonce HTML'de görünüyor',
                                recommendation='Nonce'i her istekte yenile',
                                poc='Page sourceında nonce'i gör',
                                cwe='CWE-346',
                            )
        except Exception as e:
            logger.debug(f"CSP bypass testi hatası: {str(e)}")
        
        return None
