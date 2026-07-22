#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Information Disclosure Detector
"""

from typing import List, Dict, Any
from loguru import logger
import re

from .base import BaseDetector


class InformationDisclosureDetector(BaseDetector):
    """Information Disclosure Tespiti"""
    
    SENSITIVE_PATHS = [
        '/.well-known/security.txt',
        '/robots.txt',
        '/.git/config',
        '/.env',
        '/config.php',
        '/web.config',
        '/package.json',
        '/.aws/credentials',
        '/application.yml',
        '/application.properties',
    ]
    
    SENSITIVE_PATTERNS = [
        (r'aws_access_key_id', 'AWS Credentials'),
        (r'api[_-]?key["\']?\s*[:=]', 'API Key'),
        (r'password["\']?\s*[:=]', 'Password'),
        (r'secret["\']?\s*[:=]', 'Secret'),
        (r'database[_-]?url', 'Database URL'),
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Information disclosure scanning
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan information disclosure
        """
        vulnerabilities = []
        logger.debug(f"🐛 Information Disclosure taraması başlanıyor: {url}")
        
        try:
            base_url = url.split('?')[0].rstrip('/')
            
            # Sensitive paths kontrol
            for path in self.SENSITIVE_PATHS:
                test_url = base_url + path
                response = await self._get(test_url)
                
                if response and len(response) > 10:
                    # Sensitive pattern ara
                    for pattern, info_type in self.SENSITIVE_PATTERNS:
                        if re.search(pattern, response, re.IGNORECASE):
                            vuln = self._create_vulnerability(
                                type_=f'Information Disclosure ({info_type})',
                                severity='High',
                                url=test_url,
                                description=f'{info_type} exposed: {path}',
                                recommendation='Sensitive files sunucudan uzaklaştır',
                                poc=path,
                                cwe='CWE-200',
                                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                            )
                            vulnerabilities.append(vuln)
                            break
        
        except Exception as e:
            logger.debug(f"❌ Information Disclosure tarama hatası: {str(e)}")
        
        return vulnerabilities
