# 🎯 Kartavçı - Bug Bounty Hunting Tool

Profesyonel web uygulaması zafiyeti tarama ve raporlama aracı.

## ✨ Özellikler

### 🔍 Keşif & Analiz
- **Subdomain Keşfi** - Tüm subdomainleri bul
- **Tech Stack Tespiti** - Kullanılan teknolojileri tanı
- **JavaScript Analizi** - API key ve secret'ları bul
- **Directory Brute-force** - Gizli dizinleri tara
- **Screenshot Alma** - Web sayfası görüntüsü al
- **Log Analizi** - Apache/Nginx logları analiz et

### 🐛 Zafiyet Taraması
- **CVSS 3.1 Hesaplayıcı** - Otomatik risk skorlaması
- **SQLi Tespiti** - SQL Injection zafiyeti
- **XSS Tespiti** - Cross-Site Scripting
- **IDOR Tespiti** - Yetkilendirme bypass
- **LFI Tespiti** - Local File Inclusion
- **SSRF Tespiti** - Server-Side Request Forgery
- **Auth Bypass** - Kimlik doğrulama zafiyetleri
- **CORS Misconfiguration** - CORS hatası tespiti
- **Security Headers** - CSP, HSTS kontrolü
- **SSL/TLS Analizi** - Şifreleme zafiyeti
- **Subdomain Takeover** - Boşta kalan subdomain
- **Cloud Misconfiguration** - S3, Azure, GCP
- **Git Exposure** - `.git` dizini tespiti
- **JWT Token Analizi** - Token zafiyeti

### 📊 Rapor & Ödül
- **PoC Üretimi** - Adım adım proof of concept
- **Otomatik Rapor** - HackerOne, Bugcrowd, Intigriti formatı
- **Ödül Tahmini** - Zafiyet seviyesine göre
- **İmpact Analizi** - Detaylı etki değerlendirmesi

### 🤖 İleri Özellikler
- **Ollama AI** - Zafiyet analizi ve rapor iyileştirme
- **HaveIBeenPwned** - E-posta sızıntı kontrolü
- **Shodan Entegrasyonu** - IP/device araması
- **Telegram/Discord Bot** - Gerçek zamanlı bildirim
- **Web Dashboard** - Streamlit arayüzü
- **Network Graph** - İlişki haritalaması

### ⚙️ Teknik Özellikler
- **Asenkron İşlemler** - Hızlı tarama
- **Proxy Desteği** - HTTP, SOCKS5
- **Rate Limiting** - Etik tarama
- **User-Agent Rotasyonu** - İdentifikasyon önleme
- **Session Yönetimi** - Cookie & token
- **Retry Mekanizması** - Başarısız istekleri tekrarla
- **JSON/CSV/XML Export** - Çoklu format desteği

## 📦 Kurulum

```bash
git clone https://github.com/resulekrem61/deneme.git
cd deneme
pip install -r requirements.txt
```

## 🚀 Kullanım

### CLI
```bash
# Temel tarama
python kartavci_bb.py --url https://example.com

# Full scan
python kartavci_bb.py --url https://example.com --scan full

# Özel rapor
python kartavci_bb.py --url https://example.com --report hackerone

# Dashboard
python dashboard.py
```

### Bot Kullanımı
```bash
# Telegram Bot
python bot_telegram.py

# Discord Bot
python bot_discord.py
```

## 📋 Yapılandırma

`config.yaml` dosyasını düzenle:
```yaml
scope:
  urls:
    - example.com
    - '*.example.com'
  exclude:
    - logout
    - admin

api_keys:
  shodan: "YOUR_KEY"
  hackerone: "YOUR_KEY"
  
rate_limit:
  requests_per_second: 5
  concurrent_requests: 10
```

## ⚠️ ETİK KURALLAR

- ✅ Sadece izin verilen scope'ta tarama yap
- ✅ Rate limit'e uy
- ✅ Responsible disclosure uygula
- ✅ Veri gizliliğini koru
- ❌ İzinsiz erişim yapma
- ❌ Hizmet kesintisi yaratma

## 📄 Lisans

MIT License - Detaylar için LICENSE dosyasına bak

## 👨‍💻 Geliştirici

Resulekrem61

---

**⭐ Yararlı bulduysan star ver!**
