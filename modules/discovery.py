#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Discovery ve Tech Stack Detection
"""

import asyncio
import aiohttp
import re
from typing import List, Set, Dict, Any
from loguru import logger
from urllib.parse import urlparse

from config.settings import Settings


class SubdomainDiscovery:
    """Subdomain Keşfi"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.session: asyncio.AbstractEventLoop = None
    
    async def discover(self, domain: str) -> List[str]:
        """
        Subdomainleri keşfet
        
        Args:
            domain: Hedef domain
        
        Returns:
            Bulunan subdomainler
        """
        logger.info(f"🔍 Subdomainler keşfediliyor: {domain}")
        subdomains = set()
        
        try:
            # DNS brute-force
            subdomains.update(await self._dns_bruteforce(domain))
            
            # Certificate transparency (CT) logs
            subdomains.update(await self._certificate_transparency(domain))
            
            # Google dork
            subdomains.update(await self._google_dork(domain))
            
            logger.info(f"✅ {len(subdomains)} subdomain bulundu")
            return list(subdomains)
        
        except Exception as e:
            logger.error(f"❌ Subdomain discovery hatası: {str(e)}")
            return []
    
    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """DNS brute-force"""
        subdomains = set()
        common_subs = [
            'www', 'mail', 'api', 'admin', 'test', 'staging',
            'dev', 'stage', 'prod', 'cdn', 'ftp', 'smtp',
            'imap', 'vpn', 'git', 'jenkins', 'backup', 'db'
        ]
        
        try:
            import socket
            for sub in common_subs:
                test_domain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(test_domain)
                    subdomains.add(test_domain)
                    logger.debug(f"✅ Found: {test_domain}")
                except socket.gaierror:
                    pass
        except Exception as e:
            logger.debug(f"DNS brute-force hatası: {str(e)}")
        
        return subdomains
    
    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate Transparency logsından subdomainler"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            for entry in data:
                                names = entry.get('name_value', '').split('\n')
                                for name in names:
                                    if domain in name:
                                        subdomains.add(name.strip())
                        except:
                            pass
        except Exception as e:
            logger.debug(f"CT logs hatası: {str(e)}")
        
        return subdomains
    
    async def _google_dork(self, domain: str) -> Set[str]:
        """Google Dork ile subdomain bulma"""
        # Not: Gerçek uygulamada rate limiting dikkat edilmelidir
        return set()


class TechStackDetection:
    """Tech Stack Tespiti (Wappalyzer, WhatWeb)"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, List[Dict]]:
        """Tech pattern'lerini yükle"""
        return {
            'JavaScript Frameworks': [
                {'name': 'React', 'pattern': r'react@|react/dist'},
                {'name': 'Vue.js', 'pattern': r'vue@|vue\.js'},
                {'name': 'Angular', 'pattern': r'angular@|/@angular'},
                {'name': 'Next.js', 'pattern': r'next@|__NEXT_DATA__'},
            ],
            'Backend': [
                {'name': 'Node.js', 'pattern': r'X-Powered-By.*Node'},
                {'name': 'Django', 'pattern': r'X-Powered-By.*Django'},
                {'name': 'Flask', 'pattern': r'X-Powered-By.*Flask'},
                {'name': 'Laravel', 'pattern': r'XSRF-TOKEN|laravel'},
                {'name': 'Rails', 'pattern': r'X-Runtime'},
            ],
            'Servers': [
                {'name': 'Nginx', 'pattern': r'Server.*nginx'},
                {'name': 'Apache', 'pattern': r'Server.*Apache'},
                {'name': 'IIS', 'pattern': r'Server.*IIS'},
            ],
            'CMS': [
                {'name': 'WordPress', 'pattern': r'wp-content|wp-includes'},
                {'name': 'Drupal', 'pattern': r'drupal|sites/default'},
                {'name': 'Joomla', 'pattern': r'joomla|components/'},
            ]
        }
    
    async def detect(self, url: str) -> List[Dict[str, str]]:
        """
        Tech stack'i tespit et
        
        Args:
            url: Hedef URL
        
        Returns:
            Kullanılan teknolojiler
        """
        logger.info(f"🛠️ Tech stack tespiti başlanıyor: {url}")
        tech_stack = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    headers = resp.headers
                    
                    # Headers kontrol
                    for category, techs in self.patterns.items():
                        for tech in techs:
                            # Header'da ara
                            for header_name, header_value in headers.items():
                                if re.search(tech['pattern'], f"{header_name}: {header_value}", re.IGNORECASE):
                                    tech_stack.append({
                                        'name': tech['name'],
                                        'category': category,
                                        'confidence': 'High'
                                    })
                            
                            # Content'de ara
                            if re.search(tech['pattern'], content, re.IGNORECASE):
                                if {'name': tech['name']} not in tech_stack:
                                    tech_stack.append({
                                        'name': tech['name'],
                                        'category': category,
                                        'confidence': 'Medium'
                                    })
        
        except Exception as e:
            logger.error(f"❌ Tech detection hatası: {str(e)}")
        
        logger.info(f"✅ {len(tech_stack)} teknoloji tespit edildi")
        return tech_stack
