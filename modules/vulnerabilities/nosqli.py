#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NoSQL Injection Detector
"""

import json
from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class NoSQLiDetector(BaseDetector):
    """NoSQL Injection Zafiyeti Tespiti (MongoDB, Redis, vb.)"""
    
    NOSQL_PAYLOADS = {
        'mongodb': [
            '{"$ne": null}',
            '{"$ne": ""}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "this.password == 1"}',
        ],
        'redis': [
            "'; FLUSHALL; '",
            "\x00\x01\x00\x00\x00\x05\x00\x00FLUSHALL",
        ],
        'elasticsearch': [
            '{"query": {"match_all": {}}}',
            '{"query": {"bool": {"must": [{"match_all": {}}]}}}',
        ]
    }
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        NoSQL Injection taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan NoSQL injection zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 NoSQL Injection taraması başlanıyor: {url}")
        
        try:
            # JSON payload'ları test et
            for db_type, payloads in self.NOSQL_PAYLOADS.items():
                for payload in payloads:
                    test_url = f"{url}?search={payload}"
                    response = await self._post(test_url, data={'query': payload})
                    
                    if response and ('error' not in response.lower() or len(response) > 100):
                        vuln = self._create_vulnerability(
                            type_=f'NoSQL Injection ({db_type})',
                            severity='High',
                            url=url,
                            description=f'{db_type} NoSQL Injection zafiyeti',
                            recommendation='Giriş doğrulaması ve sanitizasyonu yap',
                            poc=payload,
                            cwe='CWE-943',
                            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                        )
                        vulnerabilities.append(vuln)
                        break
        
        except Exception as e:
            logger.debug(f"❌ NoSQL Injection tarama hatası: {str(e)}")
        
        return vulnerabilities
