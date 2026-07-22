#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OLLAMA AI Integration for Vulnerability Analysis
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional
from loguru import logger

from config.settings import Settings


class OllamaAnalyzer:
    """Ollama AI for Vulnerability Analysis and PoC Generation"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.ollama_url = settings.api_keys.ollama_url
        self.model = "mistral"  # Varsayılan model
    
    async def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """
        Zafiyet analizi yapan AI prompt
        
        Args:
            vulnerability: Zafiyet detayları
        
        Returns:
            AI tarafından üretilen analiz
        """
        prompt = f"""
        Aşağıdaki web uygulaması zafiyetini analiz et ve Türkçe olarak açıkla:
        
        Zafiyet Tipi: {vulnerability.get('type')}
        Açıklama: {vulnerability.get('description')}
        CWE: {vulnerability.get('cwe')}
        Impact: {vulnerability.get('impact', 'N/A')}
        
        Analiz:
        1. Teknik açıklaması
        2. Olası saldırı senaryosu
        3. İş etkisi
        4. Ön çalışması (PoC adımları)
        """
        
        return await self._query_ollama(prompt)
    
    async def generate_poc(self, vulnerability: Dict[str, Any]) -> str:
        """
        Zafiyet için otomatik PoC üretimi
        
        Args:
            vulnerability: Zafiyet detayları
        
        Returns:
            Üretilen PoC kodu
        """
        prompt = f"""
        Aşağıdaki web uygulaması zafiyeti için adım adım Proof of Concept oluştur:
        
        Zafiyet: {vulnerability.get('type')}
        URL: {vulnerability.get('url')}
        Açıklama: {vulnerability.get('description')}
        
        Lütfen:
        1. cURL komutları ile örnek exploitation
        2. Python script ile yapılış
        3. Potansiyel impact
        """
        
        return await self._query_ollama(prompt)
    
    async def suggest_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """
        Zafiyet için remediation önerileri
        
        Args:
            vulnerability: Zafiyet detayları
        
        Returns:
            Remediation önerileri
        """
        prompt = f"""
        Aşağıdaki web uygulaması zafiyetinin düzeltilmesi için teknik öneriler yap:
        
        Zafiyet: {vulnerability.get('type')}
        CWE: {vulnerability.get('cwe')}
        
        Lütfen:
        1. Kod seviyesinde düzeltmeler
        2. Güvenlik best practices
        3. Test yöntemleri
        4. Compliance gereksinimleri
        """
        
        return await self._query_ollama(prompt)
    
    async def _query_ollama(self, prompt: str) -> str:
        """
        Ollama API'ye sorgu gönder
        
        Args:
            prompt: Prompt metni
        
        Returns:
            AI yanıtı
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                }
                
                async with session.post(
                    f"{self.ollama_url}/api/generate",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('response', '')
                    else:
                        logger.error(f"Ollama API error: {resp.status}")
                        return "Ollama API hatası"
        
        except Exception as e:
            logger.error(f"Ollama query error: {str(e)}")
            return f"Error: {str(e)}"
