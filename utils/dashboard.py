#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Dashboard (Streamlit)
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Any
import json
from datetime import datetime
from pathlib import Path


def run_dashboard():
    """Streamlit dashboard'u çalıştır"""
    st.set_page_config(
        page_title="🎯 Kartavçı Dashboard",
        page_icon="🎯",
        layout="wide"
    )
    
    # Header
    st.markdown("""
    # 🎯 Kartavçı - Bug Bounty Dashboard
    Profesyonel web uygulaması zafiyeti tarama ve raporlama aracı
    """)
    
    # Sidebar
    st.sidebar.markdown("## ⚙️ Kontrol Paneli")
    
    section = st.sidebar.radio(
        "Bölüm Seç:",
        ["📊 Anasayfa", "🔍 Tarama Yap", "📋 Raporlar", "⚙️ Ayarlar", "📚 Dokümantasyon"]
    )
    
    # Bölümler
    if section == "📊 Anasayfa":
        show_dashboard()
    elif section == "🔍 Tarama Yap":
        show_scanner()
    elif section == "📋 Raporlar":
        show_reports()
    elif section == "⚙️ Ayarlar":
        show_settings()
    elif section == "📚 Dokümantasyon":
        show_documentation()


def show_dashboard():
    """Anasayfa göster"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(label="⬜ Taramalar", value="0", delta="0")
    
    with col2:
        st.metric(label="🔴 Kritik", value="0", delta="0")
    
    with col3:
        st.metric(label="🟠 Yüksek", value="0", delta="0")
    
    with col4:
        st.metric(label="🟡 Orta", value="0", delta="0")
    
    st.markdown("---")
    st.markdown("### 📈 Son Taramalar")
    st.info("Henüz tarama yapılmamıştır. Tarama yapmak için 🔍 Tarama Yap bölümüne gidin.")


def show_scanner():
    """Tarama sayfası"""
    st.markdown("### 🔍 Web Uygulaması Taraması")
    
    col1, col2 = st.columns(2)
    
    with col1:
        target_url = st.text_input(
            "🎯 Hedef URL:",
            placeholder="https://example.com",
            help="Taranacak URL'yi gir"
        )
    
    with col2:
        scan_type = st.selectbox(
            "📋 Tarama Türü:",
            ["quick", "standard", "full", "aggressive"],
            help="Tarama derinliğini seç"
        )
    
    # Tarama seçenekleri
    st.markdown("### ✅ Aktif Kontroller")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        check_sqli = st.checkbox("SQL Injection", value=True)
        check_xss = st.checkbox("Cross-Site Scripting", value=True)
        check_idor = st.checkbox("IDOR", value=True)
    
    with col2:
        check_lfi = st.checkbox("Local File Inclusion", value=True)
        check_ssrf = st.checkbox("SSRF", value=True)
        check_cors = st.checkbox("CORS", value=True)
    
    with col3:
        check_headers = st.checkbox("Security Headers", value=True)
        check_ssl = st.checkbox("SSL/TLS", value=True)
        check_git = st.checkbox("Git Exposure", value=True)
    
    # Tarama başlat
    if st.button("🚀 Taramayı Başlat", use_container_width=True):
        st.info("⏳ Tarama yapılıyor...")
        # Burada gerçek tarama kodu çalışacak
        st.success("✅ Tarama tamamlandı!")


def show_reports():
    """Raporlar sayfası"""
    st.markdown("### 📋 Tarama Raporları")
    
    tab1, tab2, tab3 = st.tabs(["📊 Genel", "🔴 Zafiyetler", "📥 İndir"])
    
    with tab1:
        st.info("Henüz rapor bulunamadı.")
    
    with tab2:
        st.info("Henüz zafiyet bulunamadı.")
    
    with tab3:
        st.markdown("**Rapor Formatları:**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📄 JSON İndir"):
                st.info("JSON dosyası indiriliyorsunuz...")
        with col2:
            if st.button("📊 CSV İndir"):
                st.info("CSV dosyası indiriliyorsunuz...")


def show_settings():
    """Ayarlar sayfası"""
    st.markdown("### ⚙️ Uygulamayıkişiselleştir")
    
    with st.form("settings_form"):
        st.markdown("#### API Anahtarları")
        shodan_key = st.text_input("Shodan API Key:", type="password")
        hackerone_key = st.text_input("HackerOne API Key:", type="password")
        
        st.markdown("#### Rate Limiting")
        rps = st.slider("İstek/saniye:", 1, 50, 5)
        timeout = st.slider("Timeout (saniye):", 5, 60, 30)
        
        st.markdown("#### Scope")
        scope_urls = st.text_area(
            "Scope URLs (Her satırda bir):",
            value="https://example.com\nhttps://*.example.com"
        )
        
        submit = st.form_submit_button("💾 Kaydet", use_container_width=True)
        if submit:
            st.success("✅ Ayarlar kaydedildi!")


def show_documentation():
    """Dokümantasyon sayfası"""
    st.markdown("""
    ### 📚 Dokümantasyon
    
    ## Özellikler
    
    ### 🔍 Keşif & Analiz
    - **Subdomain Keşfi** - Tüm subdomainleri bul
    - **Tech Stack Tespiti** - Kullanılan teknolojileri tanı
    - **JavaScript Analizi** - API key ve secret'ları bul
    - **Directory Brute-force** - Gizli dizinleri tara
    
    ### 🐛 Zafiyet Taraması
    - **SQL Injection** - SQLi zafiyeti tespiti
    - **XSS** - Cross-Site Scripting
    - **IDOR** - Insecure Direct Object Reference
    - **LFI** - Local File Inclusion
    - **SSRF** - Server-Side Request Forgery
    - **CORS** - CORS Misconfiguration
    - **Security Headers** - Eksik security headers
    - **SSL/TLS** - Zayıf şifreleme
    - **Git Exposure** - .git dizini exposed
    - **JWT** - Weak JWT secrets
    
    ### 📊 Rapor Formatları
    - HackerOne
    - Bugcrowd
    - Intigriti
    - Standart Markdown
    
    ## Kurulum
    
    ```bash
    git clone https://github.com/resulekrem61/deneme.git
    cd deneme
    pip install -r requirements.txt
    ```
    
    ## Kullanım
    
    ### CLI
    ```bash
    python kartavci_bb.py --url https://example.com
    ```
    
    ### Dashboard
    ```bash
    python dashboard.py
    ```
    
    ## ETİK KURALLAR
    ⚠️ **ÖNEMLİ:** Sadece izin verilen scope içinde tarama yapın!
    """)


if __name__ == "__main__":
    run_dashboard()
