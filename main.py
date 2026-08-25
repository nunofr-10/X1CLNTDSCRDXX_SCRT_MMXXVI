import asyncio
import os

import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

# ------------------------------------------------------------------
# Intents: activa en el Portal de Desarrolladores de Discord
# (Bot > Privileged Gateway Intents) los siguientes toggles:
#   - SERVER MEMBERS INTENT
#   - MESSAGE CONTENT INTENT
# ------------------------------------------------------------------
intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"✅ Conectado como {bot.user} (ID: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        print(f"🔄 {len(synced)} comandos slash sincronizados.")
    except Exception as e:
        print(f"❌ Error sincronizando comandos slash: {e}")


async def load_extensions():
    # cogs.tickets: extensión del sistema de tickets (panel, canal privado,
    # /close, /claim, transcripts...). No forma parte de esta entrega;
    # colócala en cogs/tickets.py siguiendo la configuración guardada por
    # el dashboard en MongoDB (bot_config).
    # cogs.security_wick: sistema de Seguridad Profesional estilo WickBot
    # (AutoMod, AntiNuke, Cuarentena, JoinGate), respeta
    # config.modules.wick_security + automod/antinuke/joingate/quarantine.
    for extension in ("cogs.tickets", "cogs.moderation", "cogs.security_wick"):
        try:
            await bot.load_extension(extension)
            print(f"📦 Extensión cargada: {extension}")
        except Exception as e:
            print(f"⚠️  No se pudo cargar la extensión '{extension}': {e}")


async def main():
    if not TOKEN:
        raise RuntimeError(
            "Falta la variable de entorno DISCORD_BOT_TOKEN. "
            "Configúrala en tu archivo .env o en el entorno de ejecución."
        )

    async with bot:
        await load_extensions()
        await bot.start(TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
