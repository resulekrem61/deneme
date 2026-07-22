#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dashboard başlatıcı
"""

import subprocess
import sys
from loguru import logger


if __name__ == "__main__":
    logger.info("🎯 Kartavçı Dashboard başlatılıyor...")
    
    try:
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "utils/dashboard.py"],
            cwd="."
        )
    except Exception as e:
        logger.error(f"Dashboard başlatma hatası: {str(e)}")
        logger.info("Streamlit yüklemek için: pip install streamlit")
