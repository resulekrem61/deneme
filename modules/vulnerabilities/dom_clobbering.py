#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOM Clobbering Detection
"""

from typing import List, Dict, Any
from loguru import logger
import re

from .base import BaseDetector


class DOMClobberingDetector(BaseDetector):
    """DOM Clobbering Vulnerability Detection"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        DOM Clobbering scanning
        
        Args:
            url: Target URL
        
        Returns:
            Found vulnerabilities
        """
        vulnerabilities = []
        logger.debug(f"🐛 DOM Clobbering taraması başlanıyor: {url}")
        
        try:
            response = await self._get(url)
            if not response:
                return vulnerabilities
            
            # getElementById kullanımı ara
            if 'getElementById' in response:
                # name/id based clobbering payloads
                clobbering_payloads = [
                    '<img id="config" src=x onerror="alert(1)">',
                    '<form id="config" onsumbit="alert(1)">',
                    '<object id="config" data="javascript:alert(1)">',
                ]
                
                for payload in clobbering_payloads:
                    test_url = f"{url}?payload={payload}"
                    test_response = await self._get(test_url)
                    
                    if test_response and payload in test_response:
                        vuln = self._create_vulnerability(
                            type_='DOM Clobbering',
                            severity='Medium',
                            url=url,
                            description='DOM Clobbering ile variable override',
                            recommendation='getElementById yerine daha güvenli method kullan',
                            poc=payload,
                            cwe='CWE-79',
                            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L'
                        )
                        vulnerabilities.append(vuln)
                        break
        
        except Exception as e:
            logger.debug(f"❌ DOM Clobbering tarama hatası: {str(e)}")
        
        return vulnerabilities
