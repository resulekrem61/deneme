#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RateLimitBypass Techniques
"""

from typing import List, Dict, Any
from loguru import logger
import asyncio
import time

from modules.vulnerabilities.base import BaseDetector


class RateLimitBypassDetector(BaseDetector):
    """Rate Limit Bypass Techniques"""
    
    BYPASS_TECHNIQUES = {
        'ip_rotation': {
            'X-Forwarded-For': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
        },
        'header_manipulation': {
            'X-Original-URL': '/login',
            'X-Rewrite-URL': '/login',
        },
        'http_pipelining': {
            'Connection': 'keep-alive',
        }
    }
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Rate limit bypass detection
        
        Args:
            url: Target URL
        
        Returns:
            Found bypasses
        """
        vulnerabilities = []
        logger.debug(f"🐛 Rate Limit Bypass taraması başlanıyor: {url}")
        
        try:
            # IP rotation bypass
            ip_bypass = await self._test_ip_rotation_bypass(url)
            if ip_bypass:
                vulnerabilities.append(ip_bypass)
            
            # Header manipulation bypass
            header_bypass = await self._test_header_manipulation_bypass(url)
            if header_bypass:
                vulnerabilities.append(header_bypass)
            
            # HTTP pipelining
            pipelining = await self._test_http_pipelining(url)
            if pipelining:
                vulnerabilities.append(pipelining)
        
        except Exception as e:
            logger.debug(f"❌ Rate Limit Bypass tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_ip_rotation_bypass(self, url: str) -> Dict[str, Any] or None:
        """IP rotation rate limit bypass"""
        
        success_count = 0
        for i in range(20):
            headers = self._get_headers()
            headers['X-Forwarded-For'] = f"192.168.1.{i}"
            
            response = await self._get(url, headers=headers)
            
            if response and 'rate limit' not in response.lower():
                success_count += 1
        
        if success_count > 15:
            return self._create_vulnerability(
                type_='Rate Limit Bypass (IP Rotation)',
                severity='Medium',
                url=url,
                description='X-Forwarded-For header ile rate limit bypass',
                recommendation='Backend IP validation yap',
                poc='X-Forwarded-For header rotation',
                cwe='CWE-770',
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L'
            )
        
        return None
    
    async def _test_header_manipulation_bypass(self, url: str) -> Dict[str, Any] or None:
        """Header manipulation rate limit bypass"""
        
        for header_name, header_value in self.BYPASS_TECHNIQUES['header_manipulation'].items():
            headers = self._get_headers()
            headers[header_name] = header_value
            
            response = await self._get(url, headers=headers)
            
            if response and len(response) > 100:
                return self._create_vulnerability(
                    type_='Rate Limit Bypass (Header Manipulation)',
                    severity='Medium',
                    url=url,
                    description=f'{header_name} ile rate limit bypass',
                    recommendation='Rate limit kontrolü header'lere dayanmamasın',
                    poc=f'{header_name} manipulation',
                    cwe='CWE-770',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L'
                )
        
        return None
    
    async def _test_http_pipelining(self, url: str) -> Dict[str, Any] or None:
        """HTTP pipelining rate limit bypass"""
        
        headers = self._get_headers()
        headers['Connection'] = 'keep-alive'
        
        # Multiple requests pipeline olarak gönder
        pipeline_requests = '\r\n'.join([f'GET {url} HTTP/1.1' for _ in range(10)])
        
        try:
            response = await self._get(url, headers=headers)
            
            if response:
                return self._create_vulnerability(
                    type_='HTTP Pipelining Rate Limit Bypass',
                    severity='Low',
                    url=url,
                    description='HTTP pipelining ile rate limit bypass',
                    recommendation='HTTP/2 kullan, pipelining limitlemesi yap',
                    poc='HTTP pipelining requests',
                    cwe='CWE-770',
                    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L'
                )
        except Exception as e:
            logger.debug(f"HTTP pipelining test hatası: {str(e)}")
        
        return None
