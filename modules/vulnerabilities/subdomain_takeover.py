#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Takeover Detector
"""

from typing import List, Dict, Any, Set
from loguru import logger
import socket
import asyncio

from .base import BaseDetector


class SubdomainTakeoverDetector(BaseDetector):
    """Subdomain Takeover Zafiyeti Tespiti"""
    
    # Vulnerable services ve karakteristik response'lar
    VULNERABLE_SERVICES = {
        'github': 'There isn\'t a GitHub Pages site here',
        'heroku': 'No such app',
        'vercel': "Invalid Vercel URL",
        'netlify': 'netlify.com',
        'azure': 'does not exist',
        'amazon': 'NoSuchBucket',
        'shopify': 'Shopify - Error',
    }
    
    async def scan(self, url: str, subdomains: List[str] = None, **kwargs) -> List[Dict[str, Any]]:
        """
        Subdomain takeover taraması
        
        Args:
            url: Hedef URL
            subdomains: Kontrol edilecek subdomain'ler
        
        Returns:
            Bulunan subdomain takeover zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Subdomain Takeover taraması başlanıyor: {url}")
        
        if not subdomains:
            return vulnerabilities
        
        try:
            for subdomain in subdomains:
                # DNS lookup yap
                try:
                    ip = socket.gethostbyname(subdomain)
                    logger.debug(f"Subdomain {subdomain} resolved to {ip}")
                    
                    # Service-specific response kontrolü
                    response = await self._get(f"https://{subdomain}")
                    
                    for service, indicator in self.VULNERABLE_SERVICES.items():
                        if response and indicator in response:
                            vuln = self._create_vulnerability(
                                type_=f'Subdomain Takeover ({service})',
                                severity='High',
                                url=f'https://{subdomain}',
                                description=f'{subdomain} {service} üzerinde claim edilebiliyor',
                                recommendation=f'Subdomainı {service}'den claim et, yada DNS'den sil',
                                poc=f'CNAME record: {subdomain}',
                                cwe='CWE-404',
                                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                            )
                            vulnerabilities.append(vuln)
                            break
                
                except socket.gaierror:
                    logger.debug(f"Subdomain {subdomain} not resolved")
                    pass
        
        except Exception as e:
            logger.debug(f"❌ Subdomain Takeover tarama hatası: {str(e)}")
        
        return vulnerabilities
