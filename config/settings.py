#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Uygulama ayarları ve konfigürasyon
"""

import os
from typing import List, Dict, Any
from pathlib import Path
import yaml
from pydantic import BaseSettings, validator


class ScopeConfig(BaseSettings):
    """Scope yapılandırması"""
    urls: List[str] = []
    wildcards: List[str] = []
    exclude_patterns: List[str] = []
    
    class Config:
        env_prefix = "SCOPE_"


class APIKeysConfig(BaseSettings):
    """API anahtarları"""
    shodan: str = ""
    censys: str = ""
    hackerone: str = ""
    bugcrowd: str = ""
    haveibeenpwned: str = ""
    ollama_url: str = "http://localhost:11434"
    
    class Config:
        env_prefix = "API_"


class RateLimitConfig(BaseSettings):
    """Rate limiting ayarları"""
    requests_per_second: int = 5
    concurrent_requests: int = 10
    timeout: int = 30
    retry_attempts: int = 3
    
    class Config:
        env_prefix = "RATELIMIT_"


class ScannerConfig(BaseSettings):
    """Scanner ayarları"""
    # Keşif
    enable_subdomain_enum: bool = True
    enable_tech_detection: bool = True
    enable_js_analysis: bool = True
    enable_directory_bruteforce: bool = False
    
    # Zafiyet taraması
    check_sqli: bool = True
    check_xss: bool = True
    check_idor: bool = True
    check_lfi: bool = True
    check_ssrf: bool = True
    check_auth_bypass: bool = True
    check_cors: bool = True
    check_headers: bool = True
    check_ssl: bool = True
    check_git_exposure: bool = True
    check_cloud_config: bool = True
    check_jwt: bool = True
    
    # Raporlama
    calculate_cvss: bool = True
    generate_poc: bool = True
    estimate_bounty: bool = True
    
    class Config:
        env_prefix = "SCANNER_"


class ProxyConfig(BaseSettings):
    """Proxy ayarları"""
    enabled: bool = False
    http_proxy: str = ""
    https_proxy: str = ""
    socks5_proxy: str = ""
    
    class Config:
        env_prefix = "PROXY_"


class Settings(BaseSettings):
    """Ana ayarlar sınıfı"""
    
    # Temel
    app_name: str = "Kartavçı"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"
    
    # Alt konfigürasyonlar
    scope: ScopeConfig = ScopeConfig()
    api_keys: APIKeysConfig = APIKeysConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    scanner: ScannerConfig = ScannerConfig()
    proxy: ProxyConfig = ProxyConfig()
    
    # Dosya yolları
    data_dir: str = "data"
    logs_dir: str = "logs"
    reports_dir: str = "reports"
    cache_dir: str = ".cache"
    
    # User-Agent
    user_agents: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]
    
    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"
    
    def __init__(self, **data):
        super().__init__(**data)
        self._create_directories()
    
    def _create_directories(self):
        """Gerekli dizinleri oluştur"""
        for dir_name in [self.data_dir, self.logs_dir, self.reports_dir, self.cache_dir]:
            Path(dir_name).mkdir(exist_ok=True)
    
    def load_from_file(self, config_path: str):
        """YAML dosyasından konfigürasyon yükle"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # Scope ayarları
            if 'scope' in config_data:
                self.scope = ScopeConfig(**config_data['scope'])
            
            # API anahtarları
            if 'api_keys' in config_data:
                self.api_keys = APIKeysConfig(**config_data['api_keys'])
            
            # Rate limit
            if 'rate_limit' in config_data:
                self.rate_limit = RateLimitConfig(**config_data['rate_limit'])
            
            # Scanner
            if 'scanner' in config_data:
                self.scanner = ScannerConfig(**config_data['scanner'])
            
            # Proxy
            if 'proxy' in config_data:
                self.proxy = ProxyConfig(**config_data['proxy'])
        
        except FileNotFoundError:
            print(f"⚠️ Config dosyası bulunamadı: {config_path}")
    
    def save_to_file(self, config_path: str):
        """Konfigürasyonu YAML dosyasına kaydet"""
        config_dict = {
            'scope': self.scope.dict(),
            'api_keys': self.api_keys.dict(),
            'rate_limit': self.rate_limit.dict(),
            'scanner': self.scanner.dict(),
            'proxy': self.proxy.dict(),
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, allow_unicode=True, default_flow_style=False)
    
    def is_url_in_scope(self, url: str) -> bool:
        """URL'nin scope içinde olup olmadığını kontrol et"""
        # Basit wildcard kontrolü
        for pattern in self.scope.urls + self.scope.wildcards:
            if self._match_pattern(url, pattern):
                # Exclude'da mı?
                for exclude in self.scope.exclude_patterns:
                    if self._match_pattern(url, exclude):
                        return False
                return True
        return False
    
    @staticmethod
    def _match_pattern(url: str, pattern: str) -> bool:
        """Wildcard pattern eşleştirmesi"""
        import fnmatch
        return fnmatch.fnmatch(url, pattern)


# Global settings instance
settings = Settings()
