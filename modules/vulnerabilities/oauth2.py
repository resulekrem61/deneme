#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAuth 2.0 / OpenID Security Analyzer
"""

from typing import List, Dict, Any
from loguru import logger
from urllib.parse import urlparse, parse_qs

from .base import BaseDetector


class OAuth2Analyzer(BaseDetector):
    """OAuth 2.0 / OpenID Security Analysis"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        OAuth 2.0 security scanning
        
        Args:
            url: OAuth authorization endpoint
        
        Returns:
            Found vulnerabilities
        """
        vulnerabilities = []
        logger.debug(f"🐛 OAuth 2.0 taraması başlanıyor: {url}")
        
        try:
            # PKCE bypass
            pkce_bypass = await self._test_pkce_bypass(url)
            if pkce_bypass:
                vulnerabilities.append(pkce_bypass)
            
            # State parameter validation
            state_bypass = await self._test_state_parameter_bypass(url)
            if state_bypass:
                vulnerabilities.append(state_bypass)
            
            # Redirect URI validation
            redirect_bypass = await self._test_redirect_uri_bypass(url)
            if redirect_bypass:
                vulnerabilities.append(redirect_bypass)
        
        except Exception as e:
            logger.debug(f"❌ OAuth 2.0 tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_pkce_bypass(self, url: str) -> Dict[str, Any] or None:
        """PKCE (Proof Key for Public Clients) bypass"""
        
        # PKCE olmadan authorization request
        test_url = f"{url}?client_id=test&response_type=code&scope=openid"
        response = await self._get(test_url)
        
        if response and 'code=' in response:
            return self._create_vulnerability(
                type_='OAuth 2.0 PKCE Bypass',
                severity='High',
                url=url,
                description='PKCE required değil - Authorization code interception',
                recommendation='PKCE implementasyonunu zorunlu yap',
                poc='PKCE parametreleri olmadan auth code al',
                cwe='CWE-863',
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'
            )
        
        return None
    
    async def _test_state_parameter_bypass(self, url: str) -> Dict[str, Any] or None:
        """State parameter validation bypass"""
        
        # State parameter olmadan
        test_url = f"{url}?client_id=test&response_type=code&scope=openid"
        response = await self._get(test_url)
        
        if response and 'code=' in response:
            return self._create_vulnerability(
                type_='OAuth 2.0 CSRF (Missing State)',
                severity='High',
                url=url,
                description='State parameter validation yok - CSRF vulnerability',
                recommendation='State parameter validation ekle',
                poc='State parameter olmadan auth',
                cwe='CWE-352',
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'
            )
        
        return None
    
    async def _test_redirect_uri_bypass(self, url: str) -> Dict[str, Any] or None:
        """Redirect URI validation bypass"""
        
        # Tamper redirect_uri
        malicious_redirects = [
            'https://attacker.com',
            'https://attacker.com/callback',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
        ]
        
        for redirect_uri in malicious_redirects:
            test_url = f"{url}?client_id=test&response_type=code&redirect_uri={redirect_uri}"
            response = await self._get(test_url)
            
            if response and 'code=' in response:
                return self._create_vulnerability(
                    type_='OAuth 2.0 Redirect URI Validation Bypass',
                    severity='Critical',
                    url=url,
                    description=f'Redirect URI validation bypass - {redirect_uri}',
                    recommendation='Redirect URI whitelist validation',
                    poc=f'Malicious redirect_uri: {redirect_uri}',
                    cwe='CWE-601',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'
                )
        
        return None
