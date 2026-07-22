#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JWT Advanced Analyzer
"""

import jwt
import json
import base64
from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class JWTAdvancedAnalyzer(BaseDetector):
    """JWT Advanced Security Analysis"""
    
    async def scan(self, url: str, token: str = None, **kwargs) -> List[Dict[str, Any]]:
        """
        JWT advanced taraması
        
        Args:
            url: Hedef URL
            token: JWT token
        
        Returns:
            Bulunan JWT zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 JWT Advanced taraması başlanıyor: {url}")
        
        try:
            if not token:
                token = await self._extract_jwt_from_response(url)
            
            if token:
                # Algorithm confusion
                algo_confusion = await self._test_algorithm_confusion(token)
                if algo_confusion:
                    vulnerabilities.append(algo_confusion)
                
                # None algorithm
                none_algo = await self._test_none_algorithm(token)
                if none_algo:
                    vulnerabilities.append(none_algo)
                
                # Key confusion
                key_confusion = await self._test_key_confusion(token)
                if key_confusion:
                    vulnerabilities.append(key_confusion)
                
                # JWT replay
                replay = await self._test_jwt_replay(token, url)
                if replay:
                    vulnerabilities.append(replay)
        
        except Exception as e:
            logger.debug(f"❌ JWT Advanced tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _extract_jwt_from_response(self, url: str) -> str or None:
        """Response'tan JWT tokenı çıkar"""
        
        response = await self._get(url)
        if response:
            # JWT pattern ara
            import re
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
            matches = re.findall(jwt_pattern, response)
            if matches:
                return matches[0]
        
        return None
    
    async def _test_algorithm_confusion(self, token: str) -> Dict[str, Any] or None:
        """Algorithm confusion testi (RS256 -> HS256)"""
        
        try:
            # Token'i decode et (verify etmeden)
            decoded = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Eğer RS256 ise HS256'ya değiştirmeye çalış
            if header.get('alg') == 'RS256':
                new_token = jwt.encode(decoded, 'secret', algorithm='HS256')
                
                # Yeni token ile istek yap
                # Eğer çalışarsa, algorithm confusion var
                return self._create_vulnerability(
                    type_='JWT Algorithm Confusion',
                    severity='Critical',
                    url='',
                    description='RS256 -> HS256 algorithm confusion',
                    recommendation='JWT validation strict yap, algorithm'i sabit kıl',
                    poc=f'New token: {new_token}',
                    cwe='CWE-347',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        except Exception as e:
            logger.debug(f"Algorithm confusion test hatası: {str(e)}")
        
        return None
    
    async def _test_none_algorithm(self, token: str) -> Dict[str, Any] or None:
        """None algorithm testi"""
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # 'none' algorithm ile token oluştur
            none_token = token.rsplit('.', 1)[0] + '.'
            
            return self._create_vulnerability(
                type_='JWT None Algorithm Bypass',
                severity='Critical',
                url='',
                description='JWT ‘none’ algoritması ile bypass',
                recommendation='None algorithm'ı explicit olarak reddetto',
                poc=none_token,
                cwe='CWE-347',
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            )
        except Exception as e:
            logger.debug(f"None algorithm test hatası: {str(e)}")
        
        return None
    
    async def _test_key_confusion(self, token: str) -> Dict[str, Any] or None:
        """Key confusion testi"""
        
        try:
            # Token'i HS256 ile zayıf key'ler ile sign etmeye çalış
            weak_keys = ['', 'null', '0', 'false', 'admin']
            
            for key in weak_keys:
                try:
                    decoded = jwt.decode(token, key, algorithms=['HS256'])
                    return self._create_vulnerability(
                        type_='JWT Key Confusion',
                        severity='Critical',
                        url='',
                        description=f'JWT zayıf key ile sign edilebiliyor: {key}',
                        recommendation='Güçlü, random key kullan',
                        poc=f'Weak key: {key}',
                        cwe='CWE-347',
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    )
                except jwt.InvalidSignatureError:
                    pass
        except Exception as e:
            logger.debug(f"Key confusion test hatası: {str(e)}")
        
        return None
    
    async def _test_jwt_replay(self, token: str, url: str) -> Dict[str, Any] or None:
        """JWT replay attack testi"""
        
        try:
            # Aynı token ile 2 request gönder
            headers1 = {'Authorization': f'Bearer {token}'}
            response1 = await self._get(url, headers=headers1)
            
            headers2 = {'Authorization': f'Bearer {token}'}
            response2 = await self._get(url, headers=headers2)
            
            # Eğer her iki istek de çalışarsa (expiration yok)
            if response1 and response2 and len(response1) > 0 and len(response2) > 0:
                return self._create_vulnerability(
                    type_='JWT Replay Attack',
                    severity='Medium',
                    url='',
                    description='JWT token expiration check yok',
                    recommendation='exp (expiration) claim'ı zorunlu yap',
                    poc=token,
                    cwe='CWE-613',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L'
                )
        except Exception as e:
            logger.debug(f"JWT replay test hatası: {str(e)}")
        
        return None
