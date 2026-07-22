#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Subdomain Discovery
"""

import asyncio
import aiohttp
from typing import List, Set
from loguru import logger
import re

from config.settings import Settings


class AdvancedSubdomainDiscovery:
    """Advanced Subdomain Enumeration"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
    
    async def discover(self, domain: str) -> Set[str]:
        """
        Advanced subdomain discovery
        
        Args:
            domain: Hedef domain
        
        Returns:
            Bulunan subdomainler
        """
        logger.info(f"🔍 Advanced Subdomain Discovery: {domain}")
        subdomains = set()
        
        try:
            # Permutation-based discovery
            perms = await self._permutation_discovery(domain)
            subdomains.update(perms)
            
            # Certificate Transparency (crt.sh)
            cts = await self._certificate_transparency(domain)
            subdomains.update(cts)
            
            # AXFR zone transfer
            axfr = await self._axfr_zone_transfer(domain)
            subdomains.update(axfr)
            
            # Wildcard discovery
            wildcards = await self._wildcard_discovery(domain)
            subdomains.update(wildcards)
        
        except Exception as e:
            logger.error(f"❌ Advanced discovery error: {str(e)}")
        
        return subdomains
    
    async def _permutation_discovery(self, domain: str) -> Set[str]:
        """Permutation-based subdomain discovery"""
        subdomains = set()
        
        common_subs = [
            'www', 'api', 'mail', 'ftp', 'admin', 'test', 'staging', 'dev',
            'prod', 'cdn', 'backup', 'db', 'git', 'jenkins', 'vpn',
            'mysql', 'postgres', 'redis', 'elastic', 'kibana', 'grafana'
        ]
        
        for sub in common_subs:
            subdomains.add(f"{sub}.{domain}")
        
        return subdomains
    
    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate Transparency logsından subdomain bulma"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            names = entry.get('name_value', '').split('\n')
                            for name in names:
                                if domain in name:
                                    subdomains.add(name.strip())
        except Exception as e:
            logger.debug(f"CT logs error: {str(e)}")
        
        return subdomains
    
    async def _axfr_zone_transfer(self, domain: str) -> Set[str]:
        """AXFR zone transfer attempt"""
        subdomains = set()
        
        try:
            import dns.zone
            import dns.resolver
            
            # NS record bul
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name, node in zone.nodes.items():
                        subdomains.add(f"{name}.{domain}")
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"AXFR transfer error: {str(e)}")
        
        return subdomains
    
    async def _wildcard_discovery(self, domain: str) -> Set[str]:
        """Wildcard DNS enumeration"""
        subdomains = set()
        
        try:
            import socket
            
            # Random subdomain test
            random_sub = f"{''.join([chr(97 + i % 26) for i in range(10)])}.{domain}"
            
            try:
                socket.gethostbyname(random_sub)
                # Eğer resolve olursa wildcard var
                logger.info(f"🔍 Wildcard DNS bulundu: {domain}")
            except socket.gaierror:
                pass
        except Exception as e:
            logger.debug(f"Wildcard discovery error: {str(e)}")
        
        return subdomains
