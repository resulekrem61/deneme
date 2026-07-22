#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zafiyet analizi ve hesaplama modülleri
"""

import math
from typing import Dict, Any
from loguru import logger


class CVSSCalculator:
    """CVSS 3.1 Hesaplayıcı"""
    
    def calculate(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        CVSS 3.1 skoru hesapla
        
        Args:
            vulnerability: Zafiyet bilgisi
        
        Returns:
            CVSS skorlama bilgisi
        """
        # Varsayılan CVSS vektörü
        cvss_vector = vulnerability.get('cvss_vector', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')
        
        try:
            # CVSS vektörünü parse et
            score = self._parse_cvss_vector(cvss_vector)
            
            return {
                'score': score,
                'vector': cvss_vector,
                'severity': self._get_severity(score),
            }
        except Exception as e:
            logger.error(f"CVSS hesaplama hatası: {str(e)}")
            return {'score': 0, 'vector': '', 'severity': 'Unknown'}
    
    def _parse_cvss_vector(self, vector: str) -> float:
        """
        CVSS vektörünü parse et ve skoru hesapla
        
        Basitleştirilmiş CVSS 3.1 hesaplaması
        """
        # Parse işlemi
        metrics = {}
        parts = vector.split('/')
        
        for part in parts[1:]:
            key, value = part.split(':')
            metrics[key] = value
        
        # Temel skoru hesapla
        score = 0.0
        
        # Base Score Computation (Basitleştirilmiş)
        av_score = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}.get(metrics.get('AV', 'N'), 0.85)
        ac_score = {'L': 0.77, 'H': 0.44}.get(metrics.get('AC', 'L'), 0.77)
        pr_score = {'N': 0.85, 'L': 0.62, 'H': 0.27}.get(metrics.get('PR', 'N'), 0.85)
        ui_score = {'N': 0.85, 'R': 0.62}.get(metrics.get('UI', 'N'), 0.85)
        s_score = {'U': 1.0, 'C': 1.0}.get(metrics.get('S', 'U'), 1.0)
        c_score = {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(metrics.get('C', 'N'), 0.0)
        i_score = {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(metrics.get('I', 'N'), 0.0)
        a_score = {'H': 0.56, 'L': 0.22, 'N': 0.0}.get(metrics.get('A', 'N'), 0.0)
        
        # Basit hesaplama (tam CVSS 3.1 algoritmasını basitleştirdik)
        impact = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))
        exploitability = av_score * ac_score * pr_score * ui_score
        
        if impact <= 0:
            score = 0.0
        else:
            scope = metrics.get('S', 'U')
            if scope == 'U':
                score = min(impact * exploitability, 10.0)
            else:
                score = min((impact * exploitability + 0.029) * 1.084, 10.0)
        
        return round(score, 1)
    
    def _get_severity(self, score: float) -> str:
        """
        CVSS skoruna göre önem derecesini belirle
        """
        if score == 0:
            return 'None'
        elif score < 4:
            return 'Low'
        elif score < 7:
            return 'Medium'
        elif score < 9:
            return 'High'
        else:
            return 'Critical'


class BountyEstimator:
    """Ödül Tahmin Editörü"""
    
    # Tahmini ödül aralıkları
    BOUNTY_RANGES = {
        'None': (0, 0),
        'Low': (50, 200),
        'Medium': (200, 1000),
        'High': (1000, 5000),
        'Critical': (5000, 100000),
    }
    
    def estimate(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Zafiyet için ödül tahmini yap
        
        Args:
            vulnerability: Zafiyet bilgisi
        
        Returns:
            Tahmini ödül bilgisi
        """
        severity = vulnerability.get('cvss', {}).get('severity', 'Low')
        min_bounty, max_bounty = self.BOUNTY_RANGES.get(severity, (0, 0))
        
        return {
            'estimated_min': f"${min_bounty}",
            'estimated_max': f"${max_bounty}",
            'average': f"${(min_bounty + max_bounty) // 2}",
            'currency': 'USD'
        }
