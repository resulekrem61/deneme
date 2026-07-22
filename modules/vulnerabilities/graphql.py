#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GraphQL Security Detector
"""

from typing import List, Dict, Any
from loguru import logger
import json

from .base import BaseDetector


class GraphQLDetector(BaseDetector):
    """GraphQL Security Zafiyeti Tespiti"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        GraphQL taraması
        
        Args:
            url: Hedef URL (GraphQL endpoint)
        
        Returns:
            Bulunan GraphQL zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 GraphQL taraması başlanıyor: {url}")
        
        try:
            # Introspection testi
            introspection = await self._test_introspection(url)
            if introspection:
                vulnerabilities.append(introspection)
            
            # Query depth attack testi
            depth_attack = await self._test_query_depth_attack(url)
            if depth_attack:
                vulnerabilities.append(depth_attack)
            
            # Batch query attack testi
            batch_attack = await self._test_batch_query_attack(url)
            if batch_attack:
                vulnerabilities.append(batch_attack)
        
        except Exception as e:
            logger.debug(f"❌ GraphQL tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_introspection(self, url: str) -> Dict[str, Any] or None:
        """GraphQL introspection testi"""
        
        introspection_query = {
            "query": """{
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }"""
        }
        
        try:
            response = await self._post(url, data=json.dumps(introspection_query))
            
            if response and '__schema' in response:
                return self._create_vulnerability(
                    type_='GraphQL Introspection Enabled',
                    severity='Medium',
                    url=url,
                    description='GraphQL introspection enable - Schema enumeration mümkün',
                    recommendation='Production'da introspection disable et',
                    poc=json.dumps(introspection_query),
                    cwe='CWE-200',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                )
        except Exception as e:
            logger.debug(f"Introspection test hatası: {str(e)}")
        
        return None
    
    async def _test_query_depth_attack(self, url: str) -> Dict[str, Any] or None:
        """Query depth DoS attack testi"""
        
        deep_query = {
            "query": "{"
                     + "user { " * 50
                     + "id name"
                     + " }" * 50 +
                     "}"
        }
        
        try:
            response = await self._post(url, data=json.dumps(deep_query))
            
            if response and 'error' not in response.lower():
                return self._create_vulnerability(
                    type_='GraphQL Query Depth Attack (DoS)',
                    severity='Medium',
                    url=url,
                    description='Deep nested query ile DoS mümkün',
                    recommendation='Query depth limiti ekle',
                    poc='Deep nested GraphQL query',
                    cwe='CWE-400',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
                )
        except Exception as e:
            logger.debug(f"Query depth test hatası: {str(e)}")
        
        return None
    
    async def _test_batch_query_attack(self, url: str) -> Dict[str, Any] or None:
        """Batch query attack testi"""
        
        batch_queries = [
            {"query": "{user(id: 1) {id name}}"},
            {"query": "{user(id: 2) {id name}}"},
            {"query": "{user(id: 3) {id name}}"},
        ] * 100
        
        try:
            response = await self._post(url, data=json.dumps(batch_queries))
            
            if response:
                return self._create_vulnerability(
                    type_='GraphQL Batch Query Attack',
                    severity='Medium',
                    url=url,
                    description='Batch query ile rate limit bypass',
                    recommendation='Batch query limitlemesi yap',
                    poc='100+ batch queries',
                    cwe='CWE-400',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:M'
                )
        except Exception as e:
            logger.debug(f"Batch query test hatası: {str(e)}")
        
        return None
