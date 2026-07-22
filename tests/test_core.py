#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite - Birim testleri
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from config.settings import Settings
from core.scanner import VulnerabilityScanner
from modules.vulnerabilities.sqli import SQLiDetector
from modules.vulnerabilities.xss import XSSDetector
from modules.analysis import CVSSCalculator, BountyEstimator


class TestSettings:
    """Ayarlar testleri"""
    
    def test_settings_initialization(self):
        """Ayarlar başlatma testi"""
        settings = Settings()
        assert settings.app_name == "Kartavçı"
        assert settings.app_version == "1.0.0"
    
    def test_url_in_scope(self):
        """URL scope testi"""
        settings = Settings()
        settings.scope.urls = ["https://example.com"]
        
        assert settings.is_url_in_scope("https://example.com")
        assert not settings.is_url_in_scope("https://other.com")


class TestCVSSCalculator:
    """CVSS Hesaplayıcı testleri"""
    
    def test_cvss_calculation(self):
        """CVSS hesaplama testi"""
        calc = CVSSCalculator()
        vuln = {
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        }
        
        result = calc.calculate(vuln)
        assert result['score'] > 0
        assert result['severity'] in ['Low', 'Medium', 'High', 'Critical']
    
    def test_severity_classification(self):
        """Önem derecesi sınıflandırması testi"""
        calc = CVSSCalculator()
        
        assert calc._get_severity(0) == 'None'
        assert calc._get_severity(2) == 'Low'
        assert calc._get_severity(5) == 'Medium'
        assert calc._get_severity(8) == 'High'
        assert calc._get_severity(9.5) == 'Critical'


class TestBountyEstimator:
    """Ödül Tahmin Editörü testleri"""
    
    def test_bounty_estimation(self):
        """Ödül tahmini testi"""
        estimator = BountyEstimator()
        vuln = {
            'cvss': {'severity': 'Critical'}
        }
        
        result = estimator.estimate(vuln)
        assert 'estimated_min' in result
        assert 'estimated_max' in result
        assert '$' in result['estimated_min']


class TestSQLiDetector:
    """SQLi Detector testleri"""
    
    @pytest.mark.asyncio
    async def test_sqli_detection(self):
        """SQLi tespiti testi"""
        settings = Settings()
        detector = SQLiDetector(settings)
        
        # Mock response
        with patch('aiohttp.ClientSession.get', new_callable=AsyncMock) as mock_get:
            mock_resp = AsyncMock()
            mock_resp.text = AsyncMock(return_value="SQL syntax error")
            mock_get.return_value.__aenter__.return_value = mock_resp
            
            # Test burada çalışacak
            # results = await detector.scan("http://example.com?id=1")


class TestXSSDetector:
    """XSS Detector testleri"""
    
    @pytest.mark.asyncio
    async def test_xss_detection(self):
        """XSS tespiti testi"""
        settings = Settings()
        detector = XSSDetector(settings)
        
        # Test case
        assert len(detector.XSS_PAYLOADS) > 0


class TestURLValidation:
    """URL Doğrulama testleri"""
    
    def test_valid_url(self):
        """Geçerli URL testi"""
        settings = Settings()
        scanner = VulnerabilityScanner(settings)
        
        assert scanner.validate_url("https://example.com")
        assert scanner.validate_url("http://example.com/path")
        assert not scanner.validate_url("invalid-url")
        assert not scanner.validate_url("")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
