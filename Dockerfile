#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker dosyası
"""

FROM python:3.11-slim

WORKDIR /app

# Sistem paketleri
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Python paketleri
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyaları
COPY . .

# Çalışma dizini
WORKDIR /app

# Port
EXPOSE 8000 8501

# Entry point
CMD ["python", "kartavci_bb.py", "--help"]
