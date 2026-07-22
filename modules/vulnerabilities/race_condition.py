#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Race Condition Detector
"""

import asyncio
from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class RaceConditionDetector(BaseDetector):
    """Race Condition Zafiyeti Tespiti (TOCTOU)"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Race condition taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan race condition zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 Race Condition taraması başlanıyor: {url}")
        
        try:
            # Concurrent request gönder
            race_cond = await self._test_race_condition(url)
            if race_cond:
                vulnerabilities.append(race_cond)
        
        except Exception as e:
            logger.debug(f"❌ Race Condition tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_race_condition(self, url: str) -> Dict[str, Any] or None:
        """Race condition testi - Concurrent requests"""
        
        try:
            # 100 concurrent request gönder
            tasks = []
            for i in range(100):
                tasks.append(self._get(f"{url}?action=claim_reward&id=1"))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Eğer birden fazla "success" response varsa
            success_count = sum(1 for r in responses if r and 'success' in r.lower())
            
            if success_count > 1:
                return self._create_vulnerability(
                    type_='Race Condition',
                    severity='High',
                    url=url,
                    description='Concurrent request'lerde TOCTOU zafiyeti',
                    recommendation='Atomik işlemler kullan, lock mekanizması ekle',
                    poc='100 concurrent request gönderme',
                    cwe='CWE-362',
                    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N'
                )
        except Exception as e:
            logger.debug(f"Race condition test hatası: {str(e)}")
        
        return None
