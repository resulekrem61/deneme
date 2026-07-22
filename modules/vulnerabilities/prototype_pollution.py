#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prototype Pollution Detector
"""

from typing import List, Dict, Any
from loguru import logger
import json

from .base import BaseDetector


class PrototypePollutionDetector(BaseDetector):
    """Prototype Pollution Zafiyeti Tespiti"""
    
    PROTOTYPE_POLLUTION_PAYLOADS = [
        '__proto__',
        'constructor',
        'prototype',
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Prototype Pollution taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan prototype pollution zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Prototype Pollution taraması başlanıyor: {url}")
        
        try:
            # JSON merge payloads
            for payload_key in self.PROTOTYPE_POLLUTION_PAYLOADS:
                payload = {
                    payload_key: {
                        'isAdmin': True,
                        'role': 'admin',
                        'bypass': True,
                    }
                }
                
                response = await self._post(url, data=json.dumps(payload))
                
                if response:
                    # Response'ta admin flag'i kontrol et
                    if 'admin' in response.lower() or 'true' in response.lower():
                        vuln = self._create_vulnerability(
                            type_='Prototype Pollution',
                            severity='High',
                            url=url,
                            description=f'Prototype pollution via {payload_key}',
                            recommendation='Object property assignment kontrolü yap, deep freeze kullan',
                            poc=json.dumps(payload),
                            cwe='CWE-1321',
                            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                        )
                        vulnerabilities.append(vuln)
                        break
        
        except Exception as e:
            logger.debug(f"❌ Prototype Pollution tarama hatası: {str(e)}")
        
        return vulnerabilities
