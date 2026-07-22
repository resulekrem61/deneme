#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI Arayüzü
"""

import click
from typing import List
from loguru import logger


class CLI:
    """Komut Satırı Arayüzü"""
    
    def __init__(self):
        self.banner = """
╭─────────────────────────────────────╮
│   🎯 KARTAVÇI - Bug Bounty Tool   │
│   v1.0.0                            │
╰─────────────────────────────────────╯
        """
    
    def show_banner(self):
        """Banner göster"""
        print(self.banner)
    
    def show_help(self):
        """Yardım göster"""
        help_text = """
KULLANIM:
  python kartavci_bb.py [SEÇENEKLER]

SEÇENEKLER:
  -u, --url URL              Hedef URL
  -l, --list FILE            URL listesi dosyası
  -s, --scan TYPE            Tarama tipi (quick, standard, full, aggressive)
  -r, --report TYPE          Rapor formatı (hackerone, bugcrowd, intigriti, standard)
  -o, --output FILE          Çıktı dosyası
  -f, --format FORMAT        Çıktı formatı (json, csv, xml, html)
  -c, --config FILE          Konfigürasyon dosyası
  --dashboard                Web dashboard aç
  -v, --verbose              Verbose mod
  --version                  Sürüm göster
  -h, --help                 Bu yardımı göster

ÖRNEKLER:
  # Basit tarama
  python kartavci_bb.py -u https://example.com
  
  # Full tarama ve HackerOne raporu
  python kartavci_bb.py -u https://example.com -s full -r hackerone -o report.md
  
  # Maksimal tarama
  python kartavci_bb.py -u https://example.com -s aggressive --dashboard

DOKÜMENTASYON:
  https://github.com/resulekrem61/deneme
        """
        print(help_text)
