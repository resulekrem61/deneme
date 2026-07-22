# Kartavçı - Bug Bounty Tool

## 🚀 Hızlı Başlangıç

```bash
# Klonla
git clone https://github.com/resulekrem61/deneme.git
cd deneme

# Kurulumu yap
pip install -r requirements.txt

# Temel tarama yap
python kartavci_bb.py --url https://example.com

# Dashboard'u aç
python dashboard.py
```

## 📋 Özellikler

### Güvenlik Taraması
- ✅ SQL Injection (SQLi)
- ✅ Cross-Site Scripting (XSS)
- ✅ Insecure Direct Object Reference (IDOR)
- ✅ Local File Inclusion (LFI)
- ✅ Server-Side Request Forgery (SSRF)
- ✅ CORS Misconfiguration
- ✅ Security Headers Analizi
- ✅ SSL/TLS Analizi
- ✅ .git Exposure
- ✅ JWT Token Analizi

### Keşif & Analiz
- 🔍 Subdomain Keşfi
- 🛠️ Tech Stack Tespiti
- 📊 CVSS 3.1 Hesaplama
- 💰 Ödül Tahmini

### Raporlama
- 📄 HackerOne Format
- 📄 Bugcrowd Format
- 📄 Intigriti Format
- 📊 JSON, CSV, XML, HTML Export

### Bot Entegrasyonu
- 🤖 Telegram Bot
- 🤖 Discord Bot
- 🌐 Web Dashboard (Streamlit)

## 🔧 Yapılandırma

### Config Dosyası Oluştur

```bash
cp config/config.yaml.example config/config.yaml
```

### .env Dosyası

```bash
cp .env.example .env
```

Gerekli API anahtarlarını `.env` dosyasına ekle:
```
SHODAN_API_KEY=your_key
HACKERONE_API_KEY=your_key
DISCORD_BOT_TOKEN=your_token
TELEGRAM_BOT_TOKEN=your_token
```

## 💻 Kullanım

### CLI Kullanım

```bash
# Temel tarama
python kartavci_bb.py --url https://example.com

# Tam tarama
python kartavci_bb.py --url https://example.com --scan full

# HackerOne raporu ile
python kartavci_bb.py --url https://example.com --report hackerone --output report.md

# Agresif tarama
python kartavci_bb.py --url https://example.com --scan aggressive --verbose

# URL listesinden tarama
python kartavci_bb.py --list urls.txt --scan full --output results.json
```

### Web Dashboard

```bash
python dashboard.py
```

Tarayıcıda açıl: http://localhost:8501

### Telegram Bot

```bash
python bot_telegram.py
```

### Discord Bot

```bash
python bot_discord.py
```

## 📊 Çıktı Formatları

### JSON
```bash
python kartavci_bb.py --url https://example.com --format json --output results.json
```

### CSV
```bash
python kartavci_bb.py --url https://example.com --format csv --output results.csv
```

### HTML
```bash
python kartavci_bb.py --url https://example.com --format html --output report.html
```

## 🐳 Docker Kullanımı

```bash
# Image oluştur
docker build -t kartavci-bb .

# Container'ı çalıştır
docker run -it kartavci-bb

# Docker Compose ile
docker-compose up
```

## 🧪 Testler

```bash
# Testleri çalıştır
make test

# veya
pytest tests/ -v
```

## 📚 Yapı

```
deneme/
├── kartavci_bb.py              # Ana uygulama
├── dashboard.py                # Dashboard başlatıcısı
├── bot_telegram.py             # Telegram bot
├── bot_discord.py              # Discord bot
├── requirements.txt            # Python bağımlılıkları
├── setup.py                    # Kurulum dosyası
├── Dockerfile                  # Docker dosyası
├── docker-compose.yml          # Docker Compose
├── Makefile                    # Yaygın görevler
│
├── config/
│   ├── settings.py             # Ayarlar sınıfı
│   ├── config.yaml.example     # Örnek config
│
├── core/
│   ├── scanner.py              # Ana scanner
│   ├── report.py               # Rapor oluşturucu
│
├── modules/
│   ├── discovery.py            # Subdomain keşfi, tech detection
│   ├── analysis.py             # CVSS, ödül tahmini
│   ├── vulnerabilities/
│   │   ├── base.py             # Base detector
│   │   ├── sqli.py             # SQL Injection
│   │   ├── xss.py              # XSS
│   │   ├── idor.py             # IDOR
│   │   ├── lfi.py              # LFI
│   │   ├── ssrf.py             # SSRF
│   │   ├── auth_bypass.py       # Auth Bypass
│   │   ├── cors.py             # CORS
│   │   ├── headers.py          # Security Headers
│   │   ├── ssl.py              # SSL/TLS
│   │   ├── git_exposure.py     # Git Exposure
│   │   ├── cloud_config.py     # Cloud Config
│   │   └── jwt_analyzer.py     # JWT
│
├── utils/
│   ├── cli.py                  # CLI Arayüzü
│   ├── dashboard.py            # Streamlit Dashboard
│
├── tests/
│   └── test_core.py            # Birim testleri
│
├── logs/                       # Log dosyaları
├── reports/                    # Rapor dosyaları
└── data/                       # Veri dosyaları
```

## ⚠️ ETİK KURALLAR

**ÖNEMLİ:** Bu araç yalnızca izin verilen hedeflere karşı kullanılmalıdır.

- ✅ Sadece scope içinde tarama yap
- ✅ Rate limit'e uy
- ✅ Responsible disclosure uygula
- ✅ Veri gizliliğini koru
- ❌ İzinsiz erişim yapma
- ❌ Hizmet kesintisi yaratma
- ❌ Veri çalmaya veya değiştirmeye çalışma

## 🤝 Katkı

Katkılarınızı bekliyoruz! Detaylar için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun.

## 📜 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bak

## 🙏 Teşekkürler

- Bug bounty topluluğuna
- Open source katılımcılarına
- Tüm destekçilere

## 📞 İletişim

- GitHub: [@resulekrem61](https://github.com/resulekrem61)
- Issues: [GitHub Issues](https://github.com/resulekrem61/deneme/issues)

---

**⭐ Faydalı bulduysan star ver!**

*Made with ❤️ for the security community*
