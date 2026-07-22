#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Setup script - Kurulum dosyası
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="kartavci-bb",
    version="1.0.0",
    author="resulekrem61",
    author_email="your_email@example.com",
    description="🎯 Kartavçı - Professional Web Application Vulnerability Scanner & Bug Bounty Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/resulekrem61/deneme",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "asyncio-contextmanager>=1.0.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "selenium>=4.15.0",
        "playwright>=1.40.0",
        "Pillow>=10.1.0",
        "python-dotenv>=1.0.0",
        "PyYAML>=6.0.0",
        "Jinja2>=3.1.0",
        "fastapi>=0.109.0",
        "uvicorn>=0.27.0",
        "streamlit>=1.28.0",
        "plotly>=5.18.0",
        "pandas>=2.1.0",
        "numpy>=1.26.0",
        "pydantic>=2.5.0",
        "python-telegram-bot>=20.3",
        "discord.py>=2.3.0",
        "aiofiles>=23.2.0",
        "loguru>=0.7.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "tqdm>=4.67.0",
        "cryptography>=41.0.0",
        "PyJWT>=2.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.12.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
            "pylint>=3.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "kartavci=kartavci_bb:main",
        ],
    },
)
