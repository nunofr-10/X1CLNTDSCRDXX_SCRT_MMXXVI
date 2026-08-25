import os

import aiohttp
import discord
from discord.ext import commands, tasks
from motor.motor_asyncio import AsyncIOMotorClient

# ------------------------------------------------------------------
# Conexión a MongoDB Atlas (misma base de datos que usa el dashboard Flask)
# ------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI")

mongo_client = AsyncIOMotorClient(
    MONGO_URI,
    tls=True,
    tlsAllowInvalidCertificates=True,
)

db = mongo_client["discord_bot"]
config_collection = db["config"]

CONFIG_ID = "bot_config"

# Deben coincidir exactamente con BOT_STATUS_TYPES de app.py.
ACTIVITY_TYPES = {
    "playing": discord.ActivityType.playing,
    "listening": discord.ActivityType.listening,
    "watching": discord.ActivityType.watching,
    "competing": discord.ActivityType.competing,
}


async def get_config() -> dict:
    """Lee el documento de configuración compartido con el dashboard."""
    config = await config_collection.find_one({"_id": CONFIG_ID})
    return config or {}


def build_activity(status_type: str, status_text: str):
    """
    Construye el objeto discord.Activity/CustomActivity a partir del
    'Estado del bot' guardado desde el dashboard. Devuelve None si no hay
    texto configurado, lo que limpia la actividad actual del bot.
    """
    status_text = (status_text or "").strip()
    if not status_text:
        return None

    if status_type == "custom":
        return discord.CustomActivity(name=status_text)

    activity_type = ACTIVITY_TYPES.get(status_type, discord.ActivityType.playing)
    return discord.Activity(type=activity_type, name=status_text)


class BotIdentity(commands.Cog):
    """
    Aplica en vivo el 'Estado del Bot' (actividad bajo el nombre en la lista
    de miembros) y sincroniza la Descripción del perfil de la aplicación,
    ambos configurables desde el dashboard (config['bot_identity']).

    - Estado: SOLO se puede aplicar a través de la conexión Gateway del bot
      (bot.change_presence) -- el dashboard Flask no mantiene esa conexión
      abierta, así que este Cog vigila el documento de Mongo cada pocos
      segundos y lo aplica en cuanto detecta un cambio. Así queda "aplicado
      al momento" (con el margen del intervalo del bucle) y persiste hasta
      que se vuelva a cambiar.
    - Descripción: el dashboard ya la aplica al instante vía REST
      (PATCH /applications/@me) al guardar. Este Cog solo la vuelve a
      sincronizar aquí como red de seguridad -- por si ese PATCH falló o el
      documento cambió mientras el bot estaba desconectado.
    """

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._session: aiohttp.ClientSession | None = None
        self._last_applied_status = None  # tupla (status_type, status_text)
        self._last_applied_description = None

    async def cog_load(self):
        self._session = aiohttp.ClientSession()
        self.sync_loop.start()

    async def cog_unload(self):
        self.sync_loop.cancel()
        if self._session is not None:
            await self._session.close()

    @tasks.loop(seconds=15)
    async def sync_loop(self):
        try:
            config = await get_config()
        except Exception as e:
            print(f"[bot_identity] No se pudo leer la configuración: {e}")
            return

        identity = config.get("bot_identity")
        if not isinstance(identity, dict):
            return

        status_type = identity.get("status_type", "playing")
        status_text = identity.get("status_text", "")
        status_key = (status_type, status_text)

        if status_key != self._last_applied_status:
            activity = build_activity(status_type, status_text)
            try:
                await self.bot.change_presence(activity=activity)
                self._last_applied_status = status_key
            except Exception as e:
                print(f"[bot_identity] No se pudo aplicar el estado del bot: {e}")

        description = identity.get("description", "")
        if description != self._last_applied_description:
            if await self._apply_description(description):
                self._last_applied_description = description

    async def _apply_description(self, description: str) -> bool:
        """Sincroniza la descripción del perfil vía REST (PATCH /applications/@me)."""
        token = os.environ.get("DISCORD_BOT_TOKEN")
        if not token or self._session is None:
            return False
        try:
            async with self._session.patch(
                "https://discord.com/api/v10/applications/@me",
                headers={"Authorization": f"Bot {token}"},
                json={"description": description},
            ) as resp:
                return resp.status < 400
        except Exception as e:
            print(f"[bot_identity] No se pudo sincronizar la descripción: {e}")
            return False

    @sync_loop.before_loop
    async def before_sync_loop(self):
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot):
    await bot.add_cog(BotIdentity(bot))
