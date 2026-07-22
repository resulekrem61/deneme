#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSocket Security Analyzer
"""

from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class WebSocketAnalyzer(BaseDetector):
    """WebSocket Security Analysis"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        WebSocket security scanning
        
        Args:
            url: WebSocket URL (ws:// or wss://)
        
        Returns:
            Bulunan WebSocket zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 WebSocket taraması başlanıyor: {url}")
        
        try:
            # WebSocket encryption kontrolü
            encryption_check = self._check_websocket_encryption(url)
            if encryption_check:
                vulnerabilities.append(encryption_check)
            
            # CORS on WebSocket testi
            cors_check = await self._test_websocket_cors(url)
            if cors_check:
                vulnerabilities.append(cors_check)
        
        except Exception as e:
            logger.debug(f"❌ WebSocket tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    def _check_websocket_encryption(self, url: str) -> Dict[str, Any] or None:
        """WebSocket encryption kontrolü"""
        
        if url.startswith('ws://'):
            return self._create_vulnerability(
                type_='Unencrypted WebSocket',
                severity='High',
                url=url,
                description='WebSocket şifresiz iletişim (ws://)',
                recommendation='wss:// kullan',
                poc='ws:// protocol',
                cwe='CWE-295',
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
            )
        
        return None
    
    async def _test_websocket_cors(self, url: str) -> Dict[str, Any] or None:
        """WebSocket CORS testi"""
        
        # Origin header ile test
        headers = self._get_headers()
        headers['Origin'] = 'https://evil.com'
        
        try:
            response = await self._get(url, headers=headers)
            
            if response:
                return self._create_vulnerability(
                    type_='WebSocket CORS Misconfiguration',
                    severity='Medium',
                    url=url,
                    description='WebSocket CORS politikası zayıf',
                    recommendation='WebSocket CORS kontrolü ekle',
                    poc='Origin header injection',
                    cwe='CWE-346',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'
                )
        except Exception as e:
            logger.debug(f"WebSocket CORS test hatası: {str(e)}")
        
        return None
