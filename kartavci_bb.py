#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kartavçı - Bug Bounty Hunting Tool
Profesyonel web uygulaması zafiyeti tarama ve raporlama aracı
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path
from typing import Optional
from loguru import logger

from core.scanner import VulnerabilityScanner
from core.report import ReportGenerator
from config.settings import Settings
from utils.cli import CLI


class KartavciApp:
    """Ana uygulama sınıfı"""
    
    def __init__(self):
        self.settings = Settings()
        self.scanner = VulnerabilityScanner(self.settings)
        self.report_gen = ReportGenerator(self.settings)
        self.cli = CLI()
        
        # Logger ayarları
        logger.remove()
        logger.add(
            sys.stderr,
            format="<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level="INFO"
        )
        logger.add(
            "logs/kartavci.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
            level="DEBUG",
            rotation="500 MB"
        )
    
    async def scan(self, url: str, scan_type: str = "standard", output_format: str = "json") -> dict:
        """
        Tarama işlemini başlat
        
        Args:
            url: Hedef URL
            scan_type: Tarama türü (quick, standard, full, aggressive)
            output_format: Çıktı formatı (json, csv, xml, html)
        
        Returns:
            Tarama sonuçları
        """
        try:
            logger.info(f"🎯 Tarama başlanıyor: {url} [{scan_type}]")
            
            # Hedefi valide et
            if not self.scanner.validate_url(url):
                logger.error(f"❌ Geçersiz URL: {url}")
                return {"status": "error", "message": "Geçersiz URL"}
            
            # Scope kontrolü
            if not self.scanner.is_in_scope(url):
                logger.warning(f"⚠️ URL scope dışında: {url}")
                return {"status": "error", "message": "URL scope dışında"}
            
            # Tarama çalıştır
            results = await self.scanner.scan(url, scan_type)
            
            logger.info(f"✅ Tarama tamamlandı: {len(results['vulnerabilities'])} zafiyet bulundu")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Tarama hatası: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    async def generate_report(self, results: dict, format_type: str = "hackerone", 
                            output_file: Optional[str] = None) -> str:
        """
        Rapor oluştur
        
        Args:
            results: Tarama sonuçları
            format_type: Rapor formatı (hackerone, bugcrowd, intigriti, standard)
            output_file: Çıktı dosya yolu
        
        Returns:
            Rapor içeriği
        """
        try:
            logger.info(f"📝 Rapor oluşturuluyor: {format_type}")
            
            report = await self.report_gen.generate(results, format_type)
            
            if output_file:
                Path(output_file).write_text(report)
                logger.info(f"💾 Rapor kaydedildi: {output_file}")
            
            return report
            
        except Exception as e:
            logger.error(f"❌ Rapor oluşturma hatası: {str(e)}")
            return ""
    
    def parse_args(self):
        """Komut satırı argümanlarını parse et"""
        parser = argparse.ArgumentParser(
            description="🎯 Kartavçı - Bug Bounty Hunting Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Örnekler:
  %(prog)s --url https://example.com
  %(prog)s --url https://example.com --scan full --report hackerone
  %(prog)s --config config.yaml --dashboard
            """
        )
        
        parser.add_argument("-u", "--url", help="Hedef URL")
        parser.add_argument("-l", "--list", help="URL listesi dosyası")
        parser.add_argument("-s", "--scan", 
                          choices=["quick", "standard", "full", "aggressive"],
                          default="standard",
                          help="Tarama türü (default: standard)")
        parser.add_argument("-r", "--report",
                          choices=["hackerone", "bugcrowd", "intigriti", "standard"],
                          default="standard",
                          help="Rapor formatı (default: standard)")
        parser.add_argument("-o", "--output", help="Çıktı dosyası")
        parser.add_argument("-f", "--format",
                          choices=["json", "csv", "xml", "html"],
                          default="json",
                          help="Çıktı formatı (default: json)")
        parser.add_argument("-c", "--config", help="Yapılandırma dosyası")
        parser.add_argument("--dashboard", action="store_true", help="Web dashboard aç")
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mod")
        parser.add_argument("--version", action="version", version="Kartavçı 1.0.0")
        
        return parser.parse_args()
    
    async def main(self):
        """Ana fonksiyon"""
        args = self.parse_args()
        
        if args.verbose:
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")
        
        # Config dosyası yükleme
        if args.config:
            self.settings.load_from_file(args.config)
        
        # Dashboard modu
        if args.dashboard:
            from utils.dashboard import run_dashboard
            run_dashboard()
            return
        
        # URL veya liste gerekli
        if not args.url and not args.list:
            logger.error("❌ --url veya --list parametresi gerekli")
            return
        
        urls = []
        if args.url:
            urls.append(args.url)
        if args.list:
            urls.extend(Path(args.list).read_text().strip().split('\n'))
        
        # Her URL için tarama yap
        all_results = []
        for url in urls:
            results = await self.scan(url, args.scan, args.format)
            if results.get("status") != "error":
                all_results.append(results)
                
                # Rapor oluştur
                if args.report:
                    report_file = args.output or f"{url.split('//')[1]}_report.md"
                    await self.generate_report(results, args.report, report_file)
        
        # Sonuçları output'a yaz
        if all_results:
            output_data = json.dumps(all_results, indent=2, ensure_ascii=False)
            
            if args.output:
                Path(args.output).write_text(output_data)
                logger.info(f"💾 Sonuçlar kaydedildi: {args.output}")
            else:
                print(output_data)


if __name__ == "__main__":
    app = KartavciApp()
    try:
        asyncio.run(app.main())
    except KeyboardInterrupt:
        logger.warning("\n⚠️ İşlem iptal edildi (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"💥 Kritik hata: {str(e)}")
        sys.exit(1)
