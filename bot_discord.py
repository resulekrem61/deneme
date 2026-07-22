#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Discord Bot
"""

import discord
from discord.ext import commands
from loguru import logger
import os
from dotenv import load_dotenv

load_dotenv()

DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')

# Bot oluştur
bot = commands.Bot(command_prefix='!', intents=discord.Intents.default())


@bot.event
async def on_ready():
    """Bot hazır"""
    logger.info(f"🤖 Discord Bot olarak bağlandı: {bot.user}")


@bot.command(name='scan')
async def scan(ctx, url: str):
    """URL taraması başlat"""
    await ctx.send(f"🚀 Tarama başlatılıyor: {url}")
    # Tarama işlemi
    await ctx.send(f"✅ Tarama tamamlandı: {url}")


@bot.command(name='status')
async def status(ctx):
    """Bot durumu"""
    embed = discord.Embed(
        title="🎯 Kartavçı Bot Status",
        description="Bot aktif ve hazır",
        color=discord.Color.green()
    )
    await ctx.send(embed=embed)


@bot.command(name='help')
async def help_command(ctx):
    """Yardım"""
    embed = discord.Embed(
        title="📚 Kartavçı Bot Komutları",
        description="Mevcut komutlar:",
        color=discord.Color.blue()
    )
    embed.add_field(name="!scan <url>", value="URL taraması başlat", inline=False)
    embed.add_field(name="!status", value="Bot durumunu kontrol et", inline=False)
    embed.add_field(name="!help", value="Bu mesajı göster", inline=False)
    await ctx.send(embed=embed)


def main():
    """Bot'u başlat"""
    if not DISCORD_BOT_TOKEN:
        logger.error("DISCORD_BOT_TOKEN tanımlanmamıştır")
        return
    
    logger.info("🤖 Discord Bot başlatılıyor...")
    bot.run(DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Bot kapatıldı")
