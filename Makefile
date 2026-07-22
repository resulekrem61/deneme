#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Makefile - Yaygın görevler
"""

.PHONY: help install install-dev test run clean lint format

help:
	@echo "🎯 Kartavçı - Bug Bounty Tool"
	@echo ""
	@echo "Komutlar:"
	@echo "  make install         - Bağımlılıkları yükle"
	@echo "  make install-dev     - Dev bağımlılıklarını yükle"
	@echo "  make test            - Testleri çalıştır"
	@echo "  make run             - Uygulamayı çalıştır"
	@echo "  make dashboard       - Dashboard'u aç"
	@echo "  make clean           - Geçici dosyaları sil"
	@echo "  make lint            - Kod kontrolü yap"
	@echo "  make format          - Kodu formatla"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -e .[dev]

test:
	pytest tests/ -v --cov=.

run:
	python kartavci_bb.py --help

dashboard:
	streamlit run utils/dashboard.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/

format:
	black .

lint:
	flake8 .
	pylint kartavci_bb.py core/ modules/

mypy:
	mypy . --ignore-missing-imports

docker-build:
	docker build -t kartavci-bb .

docker-run:
	docker run -it kartavci-bb

docker-compose-up:
	docker-compose up

docker-compose-down:
	docker-compose down
