#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS S3 Bucket Enumeration
"""

import asyncio
from typing import List, Dict, Any
from loguru import logger

from .base import BaseDetector


class S3BucketEnumerator(BaseDetector):
    """AWS S3 Bucket Enumeration"""
    
    async def scan(self, domain: str, **kwargs) -> List[Dict[str, Any]]:
        """
        S3 bucket enumeration
        
        Args:
            domain: Hedef domain
        
        Returns:
            Bulunan S3 bucketleri ve açık config'ler
        """
        vulnerabilities = []
        logger.debug(f"🐛 S3 Bucket Enumeration başlanıyor: {domain}")
        
        try:
            # Bucket name varyasyonları
            bucket_names = [
                domain.replace('.', '-'),
                f"{domain.split('.')[0]}-backup",
                f"{domain.split('.')[0]}-dev",
                f"{domain.split('.')[0]}-prod",
                f"{domain.split('.')[0]}-staging",
                f"{domain.split('.')[0]}-data",
            ]
            
            for bucket in bucket_names:
                # Bucket açık mı kontrol et
                is_public = await self._check_bucket_public(bucket)
                if is_public:
                    vuln = self._create_vulnerability(
                        type_='AWS S3 Bucket Exposed',
                        severity='Critical',
                        url=f'https://{bucket}.s3.amazonaws.com',
                        description=f'S3 bucket {bucket} herkese açık',
                        recommendation='S3 bucket policy kontrolü yap',
                        poc=f'https://{bucket}.s3.amazonaws.com',
                        cwe='CWE-732',
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"❌ S3 Bucket enumeration hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _check_bucket_public(self, bucket_name: str) -> bool:
        """S3 bucket'ın public olup olmadığını kontrol et"""
        
        try:
            url = f'https://{bucket_name}.s3.amazonaws.com/'
            response = await self._get(url, timeout=5)
            
            # Public ise XML listing döner
            if response and 'ListBucketResult' in response:
                return True
        except Exception as e:
            logger.debug(f"Bucket check hatası: {str(e)}")
        
        return False
