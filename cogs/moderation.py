import datetime
import os

import discord
from discord import app_commands
from discord.ext import commands, tasks
from motor.motor_asyncio import AsyncIOMotorClient

# ------------------------------------------------------------------
# Conexión a MongoDB Atlas (misma base de datos que usa el dashboard Flask)
# ------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI")
# Debe coincidir con el MONGO_DB_NAME configurado en el despliegue de Flask
# de este mismo entorno (dev o producción) -- así el bot y el dashboard
# siempre leen/escriben la misma base de datos.
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "discord_bot")

mongo_client = AsyncIOMotorClient(
    MONGO_URI,
    tls=True,
    tlsAllowInvalidCertificates=True,
)

db = mongo_client[MONGO_DB_NAME]
config_collection = db["config"]
warns_collection = db["warns"]

CONFIG_ID = "bot_config"

# Comandos slash de este módulo, activables/desactivables y con roles
# autorizados configurables de forma individual desde el dashboard.
# Deben coincidir exactamente con las claves usadas en app.py (MODERATION_COMMANDS)
# y con los nombres de los @app_commands.command() de este archivo.
MODERATION_COMMAND_KEYS = [
    "warn",
    "warns",
    "clear-warns",
    "mute",
    "unmute",
    "kick",
    "ban",
    "clear",
]


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
async def get_config() -> dict:
    """Lee el documento de configuración compartido con el dashboard."""
    config = await config_collection.find_one({"_id": CONFIG_ID})
    return config or {}


def modulo_activo(config: dict, key: str) -> bool:
    """
    Comprueba si un módulo completo (ej. "moderation", "tickets") está
    encendido, leyendo config['modules'][key] -- la misma estructura que
    guarda el dashboard (app.py) desde la barra flotante de cambios sin
    guardar de modules.html.

    Mantiene compatibilidad con documentos antiguos guardados antes de
    introducir el bloque "modules", que usaban campos planos como
    moderation_enabled / tickets_enabled.
    """
    modules = config.get("modules")
    if isinstance(modules, dict) and key in modules:
        return bool(modules[key])

    legacy_field = {"moderation": "moderation_enabled", "tickets": "tickets_enabled"}.get(key)
    if legacy_field and legacy_field in config:
        return bool(config[legacy_field])

    return True


async def es_mod(interaction: discord.Interaction) -> bool:
    """
    Comprobación general de staff (sin distinguir por comando):
      - Administrador, o
      - Gestionar Mensajes, o
      - Alguno de los roles guardados en config.staff_roles.

    Se mantiene por compatibilidad; los comandos de este cog usan
    puede_usar_comando(), que además respeta el activar/desactivar y los
    roles específicos por comando configurados en el dashboard.
    """
    member = interaction.user
    if not isinstance(member, discord.Member):
        return False

    perms = member.guild_permissions
    if perms.administrator or perms.manage_messages:
        return True

    config = await get_config()
    staff_roles = set(config.get("staff_roles", []))
    if not staff_roles:
        return False

    member_role_ids = {str(role.id) for role in member.roles}
    return not staff_roles.isdisjoint(member_role_ids)


async def puede_usar_comando(interaction: discord.Interaction, command_key: str) -> bool:
    """
    Verificación granular por comando. Devuelve True si el usuario puede
    ejecutar `command_key` (ej. "warn", "clear-warns", "mute"...):

      1. Administrador o Gestionar Mensajes -> siempre permitido.
      2. Si el módulo de Moderación está desactivado -> denegado.
      3. Si el comando específico está desactivado (config.commands[key].enabled) -> denegado.
      4. Si el comando tiene roles propios asignados (config.commands[key].roles),
         solo esos roles pueden usarlo.
      5. Si el comando NO tiene roles propios, se usan los roles generales de
         staff (config.staff_roles) como respaldo.
    """
    member = interaction.user
    if not isinstance(member, discord.Member):
        return False

    perms = member.guild_permissions
    if perms.administrator or perms.manage_messages:
        return True

    config = await get_config()

    if not modulo_activo(config, "moderation"):
        return False

    cmd_cfg = (config.get("commands") or {}).get(command_key, {})
    if not cmd_cfg.get("enabled", True):
        return False

    member_role_ids = {str(role.id) for role in member.roles}

    command_roles = set(cmd_cfg.get("roles", []))
    if command_roles:
        return not command_roles.isdisjoint(member_role_ids)

    # Sin roles específicos para este comando: usar los roles generales de staff
    staff_roles = set(config.get("staff_roles", []))
    if staff_roles:
        return not staff_roles.isdisjoint(member_role_ids)

    return False


def build_log_embed(
    accion: str,
    usuario: discord.abc.User,
    moderador: discord.abc.User,
    motivo: str,
    color: discord.Color = discord.Color.blurple(),
) -> discord.Embed:
    embed = discord.Embed(
        title=f"⚠️ {accion}",
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="Usuario", value=f"{usuario.mention} ({usuario.id})", inline=False)
    embed.add_field(name="Moderador", value=f"{moderador.mention} ({moderador.id})", inline=False)
    embed.add_field(name="Motivo", value=motivo or "Sin motivo especificado", inline=False)
    embed.set_thumbnail(url=usuario.display_avatar.url)
    return embed


async def enviar_log(guild: discord.Guild, embed: discord.Embed) -> None:
    """Envía el embed de log al canal guardado en config.mod_log_channel_id, si existe."""
    config = await get_config()
    channel_id = config.get("mod_log_channel_id")
    if not channel_id:
        return

    channel = guild.get_channel(int(channel_id))
    if channel is None:
        return

    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        pass


# ------------------------------------------------------------------
# Cog de Moderación
# ------------------------------------------------------------------
class Moderation(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._last_commands_snapshot = None
        self.sync_commands_loop.start()

    def cog_unload(self):
        self.sync_commands_loop.cancel()

    async def _require_command(self, interaction: discord.Interaction, command_key: str) -> bool:
        """Verifica permisos para un comando concreto y responde con un error ephemeral si no los tiene."""
        if await puede_usar_comando(interaction, command_key):
            return True
        await interaction.response.send_message(
            "🚫 No tienes permisos para usar este comando, o está desactivado en el dashboard.",
            ephemeral=True,
        )
        return False

    # ---------------------------------------------------------------
    # Sincronización dinámica: oculta en Discord los comandos (o todo el
    # módulo) que estén desactivados en el dashboard, sin reiniciar el bot.
    # ---------------------------------------------------------------
    @tasks.loop(seconds=60)
    async def sync_commands_loop(self):
        try:
            await self._apply_command_visibility()
        except Exception as e:
            print(f"⚠️  Error sincronizando comandos de Moderación: {e}")

    @sync_commands_loop.before_loop
    async def before_sync_commands_loop(self):
        await self.bot.wait_until_ready()

    async def _apply_command_visibility(self):
        config = await get_config()
        commands_cfg = config.get("commands", {})
        moderation_enabled = modulo_activo(config, "moderation")
        guild_id = config.get("guild_id")

        # "Huella" de la config actual: si no cambió desde la última vuelta,
        # no volvemos a llamar a la API de Discord (evita rate limits).
        snapshot = (
            moderation_enabled,
            guild_id,
            tuple(
                sorted(
                    (key, bool(commands_cfg.get(key, {}).get("enabled", True)))
                    for key in MODERATION_COMMAND_KEYS
                )
            ),
        )
        if snapshot == self._last_commands_snapshot:
            return

        self._last_commands_snapshot = snapshot

        if not guild_id:
            return

        try:
            guild_obj = discord.Object(id=int(guild_id))
        except (TypeError, ValueError):
            return

        # Copia todos los comandos globales (de todos los cogs) al árbol
        # específico de este servidor, para poder quitar solo los que
        # correspondan sin afectar a otros servidores donde esté el bot.
        self.bot.tree.copy_global_to(guild=guild_obj)

        for command_key in MODERATION_COMMAND_KEYS:
            cmd_cfg = commands_cfg.get(command_key, {})
            enabled = moderation_enabled and cmd_cfg.get("enabled", True)
            if not enabled:
                self.bot.tree.remove_command(command_key, guild=guild_obj)

        try:
            await self.bot.tree.sync(guild=guild_obj)
        except discord.HTTPException as e:
            print(f"⚠️  No se pudo sincronizar comandos con el servidor {guild_id}: {e}")

    # ---------------------------------------------------------------
    # /warn
    # ---------------------------------------------------------------
    @app_commands.command(name="warn", description="Advierte a un usuario y registra el motivo.")
    @app_commands.describe(usuario="Usuario a advertir", motivo="Motivo de la advertencia")
    async def warn(self, interaction: discord.Interaction, usuario: discord.Member, motivo: str):
        if not await self._require_command(interaction, "warn"):
            return

        warn_doc = {
            "guild_id": str(interaction.guild_id),
            "user_id": str(usuario.id),
            "moderator_id": str(interaction.user.id),
            "moderator_name": str(interaction.user),
            "motivo": motivo,
            "fecha": discord.utils.utcnow(),
        }
        await warns_collection.insert_one(warn_doc)

        try:
            await usuario.send(
                f"⚠️ Has recibido una advertencia en **{interaction.guild.name}**.\n"
                f"**Motivo:** {motivo}"
            )
        except discord.Forbidden:
            pass  # El usuario tiene los DMs cerrados

        await interaction.response.send_message(
            f"✅ {usuario.mention} ha sido advertido. Motivo: {motivo}", ephemeral=True
        )

        embed = build_log_embed("Advertencia (Warn)", usuario, interaction.user, motivo, discord.Color.orange())
        await enviar_log(interaction.guild, embed)

    # ---------------------------------------------------------------
    # /warns
    # ---------------------------------------------------------------
    @app_commands.command(name="warns", description="Muestra el historial de advertencias de un usuario.")
    @app_commands.describe(usuario="Usuario a consultar")
    async def warns(self, interaction: discord.Interaction, usuario: discord.Member):
        if not await self._require_command(interaction, "warns"):
            return

        cursor = warns_collection.find(
            {"guild_id": str(interaction.guild_id), "user_id": str(usuario.id)}
        ).sort("fecha", -1)
        registros = await cursor.to_list(length=25)

        embed = discord.Embed(title=f"Historial de advertencias · {usuario}", color=discord.Color.orange())
        embed.set_thumbnail(url=usuario.display_avatar.url)

        if not registros:
            embed.description = "Este usuario no tiene advertencias registradas."
        else:
            for i, w in enumerate(registros, start=1):
                fecha = w.get("fecha")
                fecha_str = fecha.strftime("%d/%m/%Y %H:%M UTC") if fecha else "Fecha desconocida"
                embed.add_field(
                    name=f"#{i} · {fecha_str}",
                    value=(
                        f"**Motivo:** {w.get('motivo', 'Sin motivo')}\n"
                        f"**Moderador:** {w.get('moderator_name', 'Desconocido')}"
                    ),
                    inline=False,
                )

        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ---------------------------------------------------------------
    # /clear-warns
    # ---------------------------------------------------------------
    @app_commands.command(name="clear-warns", description="Elimina todas las advertencias de un usuario.")
    @app_commands.describe(usuario="Usuario a limpiar")
    async def clear_warns(self, interaction: discord.Interaction, usuario: discord.Member):
        if not await self._require_command(interaction, "clear-warns"):
            return

        result = await warns_collection.delete_many(
            {"guild_id": str(interaction.guild_id), "user_id": str(usuario.id)}
        )

        await interaction.response.send_message(
            f"🧹 Se eliminaron {result.deleted_count} advertencia(s) de {usuario.mention}.",
            ephemeral=True,
        )

        embed = build_log_embed(
            "Advertencias eliminadas",
            usuario,
            interaction.user,
            f"Se eliminaron {result.deleted_count} advertencia(s).",
            discord.Color.green(),
        )
        await enviar_log(interaction.guild, embed)

    # ---------------------------------------------------------------
    # /mute
    # ---------------------------------------------------------------
    @app_commands.command(name="mute", description="Aplica un timeout (silencio) a un usuario.")
    @app_commands.describe(usuario="Usuario a silenciar", minutos="Duración en minutos", motivo="Motivo del mute")
    async def mute(
        self,
        interaction: discord.Interaction,
        usuario: discord.Member,
        minutos: app_commands.Range[int, 1, 40320],  # máx. ~28 días, límite de Discord
        motivo: str = "Sin motivo especificado",
    ):
        if not await self._require_command(interaction, "mute"):
            return

        duracion = datetime.timedelta(minutes=minutos)
        try:
            await usuario.timeout(duracion, reason=motivo)
        except discord.Forbidden:
            await interaction.response.send_message(
                "🚫 No tengo permisos suficientes para silenciar a este usuario.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            f"🔇 {usuario.mention} ha sido silenciado durante {minutos} minuto(s). Motivo: {motivo}",
            ephemeral=True,
        )

        embed = build_log_embed(
            "Mute (Timeout)",
            usuario,
            interaction.user,
            f"{motivo}\n**Duración:** {minutos} minuto(s)",
            discord.Color.dark_grey(),
        )
        await enviar_log(interaction.guild, embed)

    # ---------------------------------------------------------------
    # /unmute
    # ---------------------------------------------------------------
    @app_commands.command(name="unmute", description="Remueve el timeout de un usuario.")
    @app_commands.describe(usuario="Usuario a desmutear")
    async def unmute(self, interaction: discord.Interaction, usuario: discord.Member):
        if not await self._require_command(interaction, "unmute"):
            return

        try:
            await usuario.timeout(None, reason=f"Unmute por {interaction.user}")
        except discord.Forbidden:
            await interaction.response.send_message(
                "🚫 No tengo permisos suficientes para desmutear a este usuario.", ephemeral=True
            )
            return

        await interaction.response.send_message(f"🔊 {usuario.mention} ya no está silenciado.", ephemeral=True)

        embed = build_log_embed("Unmute", usuario, interaction.user, "Timeout removido.", discord.Color.green())
        await enviar_log(interaction.guild, embed)

    # ---------------------------------------------------------------
    # /kick
    # ---------------------------------------------------------------
    @app_commands.command(name="kick", description="Expulsa a un usuario del servidor.")
    @app_commands.describe(usuario="Usuario a expulsar", motivo="Motivo de la expulsión")
    async def kick(
        self,
        interaction: discord.Interaction,
        usuario: discord.Member,
        motivo: str = "Sin motivo especificado",
    ):
        if not await self._require_command(interaction, "kick"):
            return

        try:
            await usuario.send(f"🚪 Has sido expulsado de **{interaction.guild.name}**.\n**Motivo:** {motivo}")
        except discord.Forbidden:
            pass

        try:
            await usuario.kick(reason=motivo)
        except discord.Forbidden:
            await interaction.response.send_message(
                "🚫 No tengo permisos suficientes para expulsar a este usuario.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            f"👢 {usuario.mention} ha sido expulsado. Motivo: {motivo}", ephemeral=True
        )

        embed = build_log_embed("Expulsión (Kick)", usuario, interaction.user, motivo, discord.Color.red())
        await enviar_log(interaction.guild, embed)

    # ---------------------------------------------------------------
    # /ban
    # ---------------------------------------------------------------
    @app_commands.command(name="ban", description="Banea a un usuario del servidor.")
    @app_commands.describe(usuario="Usuario a banear", motivo="Motivo del baneo")
    async def ban(
        self,
        interaction: discord.Interaction,
        usuario: discord.Member,
        motivo: str = "Sin motivo especificado",
    ):
        if not await self._require_command(interaction, "ban"):
            return

        try:
            await usuario.send(f"🔨 Has sido baneado de **{interaction.guild.name}**.\n**Motivo:** {motivo}")
        except discord.Forbidden:
            pass

        try:
            await usuario.ban(reason=motivo)
        except discord.Forbidden:
            await interaction.response.send_message(
                "🚫 No tengo permisos suficientes para banear a este usuario.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            f"🔨 {usuario.mention} ha sido baneado. Motivo: {motivo}", ephemeral=True
        )

        embed = build_log_embed("Baneo (Ban)", usuario, interaction.user, motivo, discord.Color.dark_red())
        await enviar_log(interaction.guild, embed)

    # ---------------------------------------------------------------
    # /clear
    # ---------------------------------------------------------------
    @app_commands.command(name="clear", description="Elimina varios mensajes del canal actual.")
    @app_commands.describe(cantidad="Cantidad de mensajes a eliminar (máx. 100)")
    async def clear(self, interaction: discord.Interaction, cantidad: app_commands.Range[int, 1, 100]):
        if not await self._require_command(interaction, "clear"):
            return

        await interaction.response.defer(ephemeral=True)
        eliminados = await interaction.channel.purge(limit=cantidad)

        await interaction.followup.send(f"🧹 Se eliminaron {len(eliminados)} mensaje(s).", ephemeral=True)

        embed = build_log_embed(
            "Purga de mensajes",
            interaction.user,
            interaction.user,
            f"Se eliminaron {len(eliminados)} mensaje(s) en {interaction.channel.mention}.",
            discord.Color.blurple(),
        )
        await enviar_log(interaction.guild, embed)


async def setup(bot: commands.Bot):
    await bot.add_cog(Moderation(bot))
