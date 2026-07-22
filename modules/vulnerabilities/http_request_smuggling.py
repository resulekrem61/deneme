#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Request Smuggling Detector
"""

from typing import List, Dict, Any
from loguru import logger
import asyncio

from .base import BaseDetector


class HTTPRequestSmugglingDetector(BaseDetector):
    """HTTP Request Smuggling Tespiti"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        HTTP Request Smuggling taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan request smuggling zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 HTTP Request Smuggling taraması başlanıyor: {url}")
        
        try:
            # CL.TE smuggling testi
            cl_te = await self._test_cl_te_smuggling(url)
            if cl_te:
                vulnerabilities.append(cl_te)
            
            # TE.CL smuggling testi
            te_cl = await self._test_te_cl_smuggling(url)
            if te_cl:
                vulnerabilities.append(te_cl)
        
        except Exception as e:
            logger.debug(f"❌ HTTP Request Smuggling tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_cl_te_smuggling(self, url: str) -> Dict[str, Any] or None:
        """CL.TE (Content-Length vs Transfer-Encoding) smuggling testi"""
        
        try:
            smuggled_request = (
                b'POST / HTTP/1.1\r\n'
                b'Host: example.com\r\n'
                b'Content-Length: 13\r\n'
                b'Transfer-Encoding: chunked\r\n'
                b'\r\n'
                b'0\r\n'
                b'\r\n'
                b'SMUGGLED'
            )
            
            response = await self._get(url)
            
            # Eğer 'SMUGGLED' response'ta görünürse
            if response and 'SMUGGLED' in response:
                return self._create_vulnerability(
                    type_='HTTP Request Smuggling (CL.TE)',
                    severity='Critical',
                    url=url,
                    description='HTTP request smuggling ile seşli istek gönderilebiliyor',
                    recommendation='Proxy ve backend arasında tutarlı protokol kullan',
                    poc='CL.TE header kombinasyonu',
                    cwe='CWE-444',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        except Exception as e:
            logger.debug(f"CL.TE test hatası: {str(e)}")
        
        return None
    
    async def _test_te_cl_smuggling(self, url: str) -> Dict[str, Any] or None:
        """TE.CL (Transfer-Encoding vs Content-Length) smuggling testi"""
        
        try:
            smuggled_request = (
                b'POST / HTTP/1.1\r\n'
                b'Host: example.com\r\n'
                b'Transfer-Encoding: chunked\r\n'
                b'Content-Length: 3\r\n'
                b'\r\n'
                b'8\r\n'
                b'SMUGGLED\r\n'
                b'0\r\n'
                b'\r\n'
            )
            
            response = await self._get(url)
            
            if response and 'SMUGGLED' in response:
                return self._create_vulnerability(
                    type_='HTTP Request Smuggling (TE.CL)',
                    severity='Critical',
                    url=url,
                    description='HTTP request smuggling ile seşli istek gönderilebiliyor',
                    recommendation='Proxy ve backend arasında tutarlı protokol kullan',
                    poc='TE.CL header kombinasyonu',
                    cwe='CWE-444',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        except Exception as e:
            logger.debug(f"TE.CL test hatası: {str(e)}")
        
        return None
