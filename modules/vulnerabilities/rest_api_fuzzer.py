#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REST API Fuzzer
"""

from typing import List, Dict, Any
from loguru import logger
import asyncio

from .base import BaseDetector


class RESTAPIFuzzer(BaseDetector):
    """REST API Fuzzing ve Testing"""
    
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
    
    HEADER_INJECTION_PAYLOADS = {
        'X-Original-URL': '/admin',
        'X-Rewrite-URL': '/admin',
        'X-Forwarded-For': '127.0.0.1',
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'localhost',
        'X-Forwarded-Server': 'localhost',
        'X-HTTP-Method-Override': 'PUT',
        'X-Method-Override': 'DELETE',
    }
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        REST API fuzzing
        
        Args:
            url: API endpoint
        
        Returns:
            Bulunan zafiyetler
        """
        vulnerabilities = []
        logger.debug(f"🐛 REST API Fuzzing başlanıyor: {url}")
        
        try:
            # HTTP method fuzzing
            method_bypass = await self._test_http_method_bypass(url)
            if method_bypass:
                vulnerabilities.append(method_bypass)
            
            # Header injection
            header_injection = await self._test_header_injection(url)
            if header_injection:
                vulnerabilities.extend(header_injection)
            
            # Content-Type manipulation
            content_type = await self._test_content_type_manipulation(url)
            if content_type:
                vulnerabilities.append(content_type)
        
        except Exception as e:
            logger.debug(f"❌ REST API Fuzzing tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_http_method_bypass(self, url: str) -> Dict[str, Any] or None:
        """HTTP method fuzzing"""
        
        for method in self.HTTP_METHODS:
            # Her HTTP method'u test et
            try:
                # Basit GET ile başla
                response = await self._get(url)
                
                # Eğer normalde 403 ise ve PUT ile 200 dönerse
                if response:
                    return self._create_vulnerability(
                        type_='HTTP Method Override',
                        severity='High',
                        url=url,
                        description=f'{method} HTTP methodu ile erişim sağlanabiliyor',
                        recommendation='HTTP method'leri whitelist ile kontrol et',
                        poc=f'{method} request',
                        cwe='CWE-648',
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'
                    )
            except Exception as e:
                logger.debug(f"{method} fuzzing hatası: {str(e)}")
        
        return None
    
    async def _test_header_injection(self, url: str) -> List[Dict[str, Any]]:
        """Header injection testi"""
        vulnerabilities = []
        
        for header_name, header_value in self.HEADER_INJECTION_PAYLOADS.items():
            headers = self._get_headers()
            headers[header_name] = header_value
            
            response = await self._get(url, headers=headers)
            
            if response and len(response) > 100:
                vuln = self._create_vulnerability(
                    type_='Header Injection',
                    severity='High',
                    url=url,
                    description=f'{header_name} header injection',
                    recommendation='Header validation yap',
                    poc=f'{header_name}: {header_value}',
                    cwe='CWE-113',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_content_type_manipulation(self, url: str) -> Dict[str, Any] or None:
        """Content-Type manipulation testi"""
        
        content_types = [
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'text/xml',
            'application/json+xml',
        ]
        
        for ct in content_types:
            headers = self._get_headers()
            headers['Content-Type'] = ct
            
            response = await self._post(url, headers=headers)
            
            if response and 'error' not in response.lower():
                return self._create_vulnerability(
                    type_='Content-Type Manipulation',
                    severity='Medium',
                    url=url,
                    description=f'Content-Type: {ct} ile bypass',
                    recommendation='Content-Type validation yap',
                    poc=f'Content-Type: {ct}',
                    cwe='CWE-436',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
                )
        
        return None
