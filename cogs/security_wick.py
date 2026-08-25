from __future__ import annotations

import asyncio
import os
import re
import time
import unicodedata
from collections import defaultdict, deque

import discord
from discord.ext import commands
from motor.motor_asyncio import AsyncIOMotorClient

# ------------------------------------------------------------------
# Conexión a MongoDB Atlas (misma base de datos que usa el dashboard Flask
# y el resto de cogs del bot).
# ------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI")
# Debe coincidir con el MONGO_DB_NAME configurado en el despliegue de Flask
# de este mismo entorno (dev o producción).
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "discord_bot")

mongo_client = AsyncIOMotorClient(
    MONGO_URI,
    tls=True,
    tlsAllowInvalidCertificates=True,
)

db = mongo_client[MONGO_DB_NAME]
config_collection = db["config"]

CONFIG_ID = "bot_config"

# Ventana de tiempo (segundos) en la que se busca en el Audit Log al
# responsable de una acción destructiva. Discord tarda un poco en registrar
# la entrada, así que se reintenta un par de veces con una pequeña espera.
AUDIT_LOG_WINDOW_SECONDS = 15
AUDIT_LOG_RETRY_DELAY = 1.2
AUDIT_LOG_RETRIES = 3

INVITE_REGEX = re.compile(
    r"(discord\.gg|discord(?:app)?\.com/invite|dsc\.gg)/[a-zA-Z0-9-]+", re.IGNORECASE
)
SCAM_DOMAIN_HINTS = (
    "steamcommunity-gift", "discord-nitro", "dlscord", "discrod", "steamcommmunity",
    "free-nitro", "discord-airdrop", "stemcommunity", "dicsord", "discordgift",
)
SUSPICIOUS_NICK_HINTS = ("discord.gg/", "nitro", "@everyone", "@here")


# ------------------------------------------------------------------
# Helpers de configuración (compartidos con el dashboard Flask)
# ------------------------------------------------------------------
async def get_config() -> dict:
    """Lee el documento de configuración compartido con el dashboard."""
    config = await config_collection.find_one({"_id": CONFIG_ID})
    return config or {}


def modulo_activo(config: dict, key: str) -> bool:
    """
    Comprueba si un módulo completo (ej. "automod", "antinuke", "joingate",
    "quarantine") está encendido, leyendo config['modules'][key]. También
    exige que el switch maestro config['modules']['wick_security'] esté
    activo -- todo el sistema depende de él.
    """
    modules = config.get("modules")
    if not isinstance(modules, dict):
        return True
    if not bool(modules.get("wick_security", True)):
        return False
    return bool(modules.get(key, True))


def _whitelist_group(config: dict, group: str) -> dict:
    whitelists = config.get("whitelists")
    if not isinstance(whitelists, dict):
        return {}
    group_data = whitelists.get(group)
    return group_data if isinstance(group_data, dict) else {}


def is_whitelisted(
    config: dict,
    group: str,
    *,
    member: discord.abc.User | discord.Member | None = None,
    channel: discord.abc.GuildChannel | None = None,
    webhook_id: str | int | None = None,
) -> bool:
    """
    True si el miembro/canal/categoría/webhook implicado está exento de la
    protección `group` (spam/invites/pings/everyone), comprobando IDs de
    miembro, roles, canal, categoría del canal y webhook contra
    config['whitelists'][group].
    """
    wl = _whitelist_group(config, group)
    if not wl:
        return False

    member_ids = {str(v) for v in wl.get("members", [])}
    role_ids = {str(v) for v in wl.get("roles", [])}
    channel_ids = {str(v) for v in wl.get("channels", [])}
    category_ids = {str(v) for v in wl.get("categories", [])}
    webhook_ids = {str(v) for v in wl.get("webhooks", [])}

    if member is not None:
        if str(member.id) in member_ids:
            return True
        if isinstance(member, discord.Member):
            member_role_ids = {str(r.id) for r in member.roles}
            if member_role_ids & role_ids:
                return True

    if channel is not None:
        if str(channel.id) in channel_ids:
            return True
        category = getattr(channel, "category", None)
        if category is not None and str(category.id) in category_ids:
            return True

    if webhook_id is not None and str(webhook_id) in webhook_ids:
        return True

    return False


def is_immune_to_quarantine(config: dict, user_id: int) -> bool:
    whitelists = config.get("whitelists")
    if not isinstance(whitelists, dict):
        return False
    immune = whitelists.get("quarantine_users")
    if not isinstance(immune, list):
        return False
    return str(user_id) in {str(v) for v in immune}


def is_category_allowed_for_creation(config: dict, category: discord.CategoryChannel | None) -> bool:
    """
    True si el canal puede crearse en esa categoría según
    whitelists.channel_creation_categories. Si la lista está vacía, no hay
    restricción configurada y se permite cualquier categoría.
    """
    whitelists = config.get("whitelists")
    allowed = whitelists.get("channel_creation_categories") if isinstance(whitelists, dict) else None
    if not isinstance(allowed, list) or not allowed:
        return True
    if category is None:
        return False
    return str(category.id) in {str(v) for v in allowed}


def contains_zalgo(text: str) -> bool:
    """Detecta texto Zalgo: exceso de caracteres unicode combinables (acentos apilados)."""
    combining = sum(1 for ch in text if unicodedata.combining(ch))
    return combining >= 8


def contains_scam_link(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in SCAM_DOMAIN_HINTS)


def count_emojis(text: str) -> int:
    custom = len(re.findall(r"<a?:\w+:\d+>", text))
    unicode_emoji = len(
        re.findall(
            r"[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF]", text
        )
    )
    return custom + unicode_emoji


# ------------------------------------------------------------------
# Cog principal
# ------------------------------------------------------------------
class SecurityWick(commands.Cog):
    """
    Sistema de Seguridad Profesional estilo WickBot: AutoMod, AntiNuke,
    Cuarentena y JoinGate. Toda la configuración se lee de config['automod'],
    config['antinuke'], config['quarantine'], config['joingate'] y
    config['whitelists'] (ver app.py -- mismo documento "bot_config" que
    edita el dashboard Flask en /security-wick).
    """

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # Historial de mensajes recientes por (canal_id, autor_id), usado
        # para detectar spam de mensajes repetidos. En memoria: se resetea
        # si el bot se reinicia, lo cual es aceptable para este propósito.
        self._recent_messages: dict[tuple[int, int], deque] = defaultdict(
            lambda: deque(maxlen=5)
        )
        # Evita procesar dos veces la misma entrada de Audit Log si llegan
        # varios eventos de gateway casi simultáneos para la misma acción.
        self._handled_audit_ids: deque = deque(maxlen=200)

    # ------------------------------------------------------------------
    # Utilidades de logging
    # ------------------------------------------------------------------
    async def _send_log(self, guild: discord.Guild, config: dict, embed: discord.Embed, *, mod_log: bool = False):
        misc = config.get("misc") if isinstance(config.get("misc"), dict) else {}
        channel_id = misc.get("mod_log_channel_id") if mod_log else misc.get("log_channel_id")
        if not channel_id:
            return
        channel = guild.get_channel(int(channel_id)) if str(channel_id).isdigit() else None
        if channel is None:
            return
        try:
            await channel.send(embed=embed)
        except discord.HTTPException:
            pass

    def _base_embed(self, title: str, description: str, color: int) -> discord.Embed:
        embed = discord.Embed(title=title, description=description, color=color)
        embed.timestamp = discord.utils.utcnow()
        return embed

    # ------------------------------------------------------------------
    # Audit Log: identificar al responsable de una acción
    # ------------------------------------------------------------------
    async def _find_responsible(
        self, guild: discord.Guild, action: discord.AuditLogAction, target_id: int | None = None
    ) -> discord.Member | discord.User | None:
        """
        Busca en el Audit Log la entrada más reciente de `action` (opcionalmente
        filtrando por target_id) ocurrida en los últimos AUDIT_LOG_WINDOW_SECONDS
        segundos, con un par de reintentos porque Discord tarda un poco en
        registrar la entrada tras el evento de gateway.
        """
        if not guild.me.guild_permissions.view_audit_log:
            return None

        for attempt in range(AUDIT_LOG_RETRIES):
            try:
                async for entry in guild.audit_logs(limit=5, action=action):
                    age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                    if age > AUDIT_LOG_WINDOW_SECONDS:
                        break
                    if target_id is not None and getattr(entry.target, "id", None) != target_id:
                        continue
                    if entry.id in self._handled_audit_ids:
                        continue
                    self._handled_audit_ids.append(entry.id)
                    return entry.user
            except discord.Forbidden:
                return None
            except discord.HTTPException:
                pass
            await asyncio.sleep(AUDIT_LOG_RETRY_DELAY)
        return None

    def _is_authorized(self, guild: discord.Guild, config: dict, user: discord.abc.User | None) -> bool:
        """
        True si `user` puede realizar acciones administrativas sin ser
        sancionado por AntiNuke: el propio bot, el dueño del servidor, o
        alguien en whitelists.quarantine_users (inmune a Cuarentena).
        """
        if user is None:
            return True  # No se pudo determinar responsable: no se castiga a nadie.
        if user.id == self.bot.user.id:
            return True
        if guild.owner_id == user.id:
            return True
        if is_immune_to_quarantine(config, user.id):
            return True
        return False

    # ------------------------------------------------------------------
    # Sanción: Cuarentena o baneo
    # ------------------------------------------------------------------
    async def _punish(self, guild: discord.Guild, config: dict, user: discord.abc.User, reason: str):
        quarantine_cfg = config.get("quarantine") if isinstance(config.get("quarantine"), dict) else {}
        quarantine_enabled = modulo_activo(config, "quarantine") and quarantine_cfg.get("enabled", True)
        quarantine_role_id = quarantine_cfg.get("quarantine_role_id")

        member = guild.get_member(user.id)

        action_taken = "ninguna"
        try:
            if quarantine_enabled and quarantine_role_id and member is not None:
                role = guild.get_role(int(quarantine_role_id)) if str(quarantine_role_id).isdigit() else None
                if role is not None:
                    await member.edit(
                        roles=[role],
                        reason=f"WickSecurity AntiNuke: {reason}",
                    )
                    action_taken = f"Rol de Cuarentena aplicado ({role.name})"
            if action_taken == "ninguna":
                # Sin rol de cuarentena configurado (o usuario ya fuera del
                # servidor): se banea como último recurso.
                await guild.ban(discord.Object(id=user.id), reason=f"WickSecurity AntiNuke: {reason}", delete_message_seconds=0)
                action_taken = "Baneado"
        except discord.Forbidden:
            action_taken = "⚠️ Sin permisos suficientes para sancionar"
        except discord.HTTPException as e:
            action_taken = f"⚠️ Error al sancionar: {e}"

        embed = self._base_embed(
            "🚨 AntiNuke: acción no autorizada detectada",
            f"**Usuario:** {user} (`{user.id}`)\n**Motivo:** {reason}\n**Sanción aplicada:** {action_taken}",
            0xED4245,
        )
        await self._send_log(guild, config, embed, mod_log=True)

    # ==================================================================
    # AUTOMOD -- on_message
    # ==================================================================
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.guild is None:
            return
        if message.author.id == self.bot.user.id:
            return

        config = await get_config()
        automod = config.get("automod") if isinstance(config.get("automod"), dict) else {}
        anti_spam = automod.get("anti_spam") if isinstance(automod.get("anti_spam"), dict) else {}

        # --- Webhooks sin lista blanca ---
        if message.webhook_id is not None:
            if (
                modulo_activo(config, "automod")
                and automod.get("enabled", True)
                and automod.get("monitor_webhooks", True)
                and not is_whitelisted(config, "spam", channel=message.channel, webhook_id=message.webhook_id)
            ):
                await self._delete_and_log(
                    message, config, "🪝 Webhook no autorizado",
                    "Mensaje de un webhook fuera de la lista blanca eliminado."
                )
            return

        if message.author.bot:
            return
        if not modulo_activo(config, "automod") or not automod.get("enabled", True):
            return

        member = message.author
        content = message.content or ""

        # --- Invitaciones de Discord ---
        if automod.get("moderate_invites") and INVITE_REGEX.search(content):
            if not is_whitelisted(config, "invites", member=member, channel=message.channel):
                await self._delete_and_log(
                    message, config, "🔗 Invitación eliminada",
                    f"Se eliminó un mensaje de {member.mention} por contener una invitación no autorizada."
                )
                return

        # --- Enlaces / links maliciosos (scam) ---
        if automod.get("filter_scam") and contains_scam_link(content):
            if not is_whitelisted(config, "spam", member=member, channel=message.channel):
                await self._delete_and_log(
                    message, config, "⚠️ Enlace malicioso eliminado",
                    f"Se eliminó un mensaje de {member.mention} por contener un enlace sospechoso de scam/phishing."
                )
                return

        # --- Menciones masivas a @everyone/@here ---
        if message.mention_everyone:
            if not is_whitelisted(config, "everyone", member=member, channel=message.channel):
                await self._delete_and_log(
                    message, config, "📢 Mención a @everyone bloqueada",
                    f"Se eliminó un mensaje de {member.mention} por mencionar a @everyone/@here sin autorización."
                )
                return

        # --- Anti-Spam ---
        if anti_spam.get("enabled", True) and not is_whitelisted(config, "spam", member=member, channel=message.channel):
            if await self._check_anti_spam(message, anti_spam, config):
                return

        # --- Pings excesivos a otros usuarios (además del anti-spam) ---
        if (
            anti_spam.get("mention_spam")
            and len(message.mentions) >= 5
            and not is_whitelisted(config, "pings", member=member, channel=message.channel)
        ):
            await self._delete_and_log(
                message, config, "📣 Exceso de menciones",
                f"Se eliminó un mensaje de {member.mention} por mencionar a demasiados usuarios de golpe."
            )
            return

    async def _check_anti_spam(self, message: discord.Message, anti_spam: dict, config: dict) -> bool:
        content = message.content or ""
        key = (message.channel.id, message.author.id)
        history = self._recent_messages[key]

        # Mensajes repetidos
        if anti_spam.get("repetitive_spam") and content:
            recent_same = sum(1 for prev, ts in history if prev == content and time.time() - ts < 15)
            if recent_same >= 2:
                await self._delete_and_log(
                    message, config, "🌊 Spam de mensajes repetidos",
                    f"Se eliminaron mensajes repetidos de {message.author.mention}."
                )
                history.clear()
                return True

        history.append((content, time.time()))

        # Adjuntos en ráfaga
        if anti_spam.get("attachment_spam") and len(message.attachments) >= 5:
            await self._delete_and_log(
                message, config, "📎 Spam de adjuntos",
                f"Se eliminó un mensaje de {message.author.mention} con demasiados archivos adjuntos."
            )
            return True

        # Mensajes muy largos
        if anti_spam.get("long_messages") and len(content) > 1500:
            await self._delete_and_log(
                message, config, "📄 Mensaje demasiado largo",
                f"Se eliminó un mensaje de {message.author.mention} por exceder la longitud permitida."
            )
            return True

        # Spam de emojis
        if anti_spam.get("emoji_spam") and count_emojis(content) >= 12:
            await self._delete_and_log(
                message, config, "😂 Spam de emojis",
                f"Se eliminó un mensaje de {message.author.mention} con demasiados emojis."
            )
            return True

        # Saltos de línea excesivos
        if anti_spam.get("new_lines_spam") and content.count("\n") >= 15:
            await self._delete_and_log(
                message, config, "📃 Spam de saltos de línea",
                f"Se eliminó un mensaje de {message.author.mention} por contener demasiados saltos de línea."
            )
            return True

        # Texto Zalgo
        if anti_spam.get("zalgo_spam") and contains_zalgo(content):
            await self._delete_and_log(
                message, config, "🌀 Texto Zalgo bloqueado",
                f"Se eliminó un mensaje de {message.author.mention} por contener texto Zalgo."
            )
            return True

        return False

    async def _delete_and_log(self, message: discord.Message, config: dict, title: str, description: str):
        try:
            await message.delete()
        except (discord.Forbidden, discord.NotFound):
            pass
        embed = self._base_embed(title, description, 0xED4245)
        embed.set_footer(text=f"Canal: #{getattr(message.channel, 'name', 'desconocido')}")
        await self._send_log(message.guild, config, embed)

    # ==================================================================
    # JOINGATE -- on_member_join
    # ==================================================================
    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        config = await get_config()
        joingate = config.get("joingate") if isinstance(config.get("joingate"), dict) else {}

        if not modulo_activo(config, "joingate") or not joingate.get("enabled", True):
            return
        if is_whitelisted(config, "everyone", member=member):
            return

        reasons = []
        account_age_hours = (discord.utils.utcnow() - member.created_at).total_seconds() / 3600

        if joingate.get("target_young_accounts") and account_age_hours < joingate.get("min_account_age_hours", 24):
            reasons.append(f"Cuenta demasiado reciente ({account_age_hours:.1f}h de antigüedad)")

        if joingate.get("target_no_pfp") and member.avatar is None:
            reasons.append("Sin foto de perfil personalizada")

        display_name = (member.nick or member.name or "").lower()
        if joingate.get("target_invite_in_name") and ("discord.gg/" in display_name or "discord.com/invite" in display_name):
            reasons.append("Invitación de Discord en el nombre de usuario")

        if joingate.get("target_suspicious_nicks") and any(hint in display_name for hint in SUSPICIOUS_NICK_HINTS):
            reasons.append("Nombre de usuario sospechoso")

        if member.bot:
            if joingate.get("target_unverified_bots") and not member.public_flags.verified_bot:
                reasons.append("Bot no verificado por Discord")
            if joingate.get("target_unauthorized_bots") and not is_whitelisted(config, "everyone", member=member):
                reasons.append("Bot no autorizado (fuera de la lista blanca)")

        if not reasons:
            return

        action = joingate.get("action", "kick")
        action_label = "ninguna"
        try:
            if action == "ban":
                await member.ban(reason="WickSecurity JoinGate: " + "; ".join(reasons), delete_message_seconds=0)
                action_label = "Baneado"
            else:
                await member.kick(reason="WickSecurity JoinGate: " + "; ".join(reasons))
                action_label = "Expulsado"
        except discord.Forbidden:
            action_label = "⚠️ Sin permisos suficientes para sancionar"
        except discord.HTTPException as e:
            action_label = f"⚠️ Error al sancionar: {e}"

        embed = self._base_embed(
            "🚪 JoinGate: miembro bloqueado",
            f"**Usuario:** {member} (`{member.id}`)\n"
            f"**Motivo(s):** {', '.join(reasons)}\n"
            f"**Acción:** {action_label}",
            0xF5C451,
        )
        await self._send_log(member.guild, config, embed, mod_log=True)

    # ==================================================================
    # ANTINUKE -- eventos de canales, roles, webhooks y baneos
    # ==================================================================
    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel):
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return
        if not antinuke.get("monitor_channel_deletes", True):
            return

        responsible = await self._find_responsible(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
        if self._is_authorized(channel.guild, config, responsible):
            return

        await self._punish(channel.guild, config, responsible, f"Eliminó el canal #{channel.name}")

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel):
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return

        category = getattr(channel, "category", None)
        category_restricted = not is_category_allowed_for_creation(config, category)

        responsible = await self._find_responsible(channel.guild, discord.AuditLogAction.channel_create, channel.id)
        authorized = self._is_authorized(channel.guild, config, responsible)

        # Canal creado fuera de las categorías permitidas (ej. bots de
        # tickets no autorizados): se elimina sin importar quién lo creó,
        # salvo que el responsable esté autorizado.
        if category_restricted and not authorized:
            try:
                await channel.delete(reason="WickSecurity AntiNuke: categoría no autorizada")
            except (discord.Forbidden, discord.NotFound):
                pass
            embed = self._base_embed(
                "🗑️ Canal eliminado automáticamente",
                f"Se eliminó **#{channel.name}** por crearse fuera de las categorías permitidas para creación de canales.",
                0xED4245,
            )
            await self._send_log(channel.guild, config, embed, mod_log=True)

        if antinuke.get("monitor_channel_creates", True) and not authorized:
            await self._punish(channel.guild, config, responsible, f"Creó el canal #{channel.name}")

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role):
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return
        if not antinuke.get("monitor_role_deletes", True):
            return

        responsible = await self._find_responsible(role.guild, discord.AuditLogAction.role_delete, role.id)
        if self._is_authorized(role.guild, config, responsible):
            return

        await self._punish(role.guild, config, responsible, f"Eliminó el rol @{role.name}")

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role):
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return
        if not antinuke.get("monitor_role_creates", True):
            return

        responsible = await self._find_responsible(role.guild, discord.AuditLogAction.role_create, role.id)
        if self._is_authorized(role.guild, config, responsible):
            return

        await self._punish(role.guild, config, responsible, f"Creó el rol @{role.name}")

    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: discord.User):
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return
        if not antinuke.get("monitor_kicks_bans", True):
            return

        responsible = await self._find_responsible(guild, discord.AuditLogAction.ban, user.id)
        if self._is_authorized(guild, config, responsible):
            return

        await self._punish(guild, config, responsible, f"Baneó a {user} (`{user.id}`)")

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member):
        """
        discord.py no distingue directamente un kick de una salida normal;
        se detecta comprobando si hay una entrada reciente de Audit Log de
        tipo `kick` con ese miembro como objetivo.
        """
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return
        if not antinuke.get("monitor_kicks_bans", True):
            return

        responsible = await self._find_responsible(member.guild, discord.AuditLogAction.kick, member.id)
        if responsible is None:
            return  # Salida voluntaria, no un kick.
        if self._is_authorized(member.guild, config, responsible):
            return

        await self._punish(member.guild, config, responsible, f"Expulsó a {member} (`{member.id}`)")

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel):
        """
        Discord no distingue creación de eliminación en este evento -- se
        determina consultando el Audit Log por ambos tipos de acción y
        quedándonos con la entrada más reciente.
        """
        config = await get_config()
        antinuke = config.get("antinuke") if isinstance(config.get("antinuke"), dict) else {}
        if not modulo_activo(config, "antinuke") or not antinuke.get("enabled", True):
            return

        guild = channel.guild
        if not guild.me.guild_permissions.view_audit_log:
            return

        created_entry = None
        deleted_entry = None
        try:
            async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.webhook_create):
                if (discord.utils.utcnow() - entry.created_at).total_seconds() <= AUDIT_LOG_WINDOW_SECONDS:
                    created_entry = entry
                break
            async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.webhook_delete):
                if (discord.utils.utcnow() - entry.created_at).total_seconds() <= AUDIT_LOG_WINDOW_SECONDS:
                    deleted_entry = entry
                break
        except (discord.Forbidden, discord.HTTPException):
            return

        entry = None
        action_desc = ""
        if created_entry and antinuke.get("monitor_webhook_creates", True):
            entry, action_desc = created_entry, "Creó un webhook"
        elif deleted_entry and antinuke.get("monitor_webhook_deletes", True):
            entry, action_desc = deleted_entry, "Eliminó un webhook"

        if entry is None or entry.id in self._handled_audit_ids:
            return
        self._handled_audit_ids.append(entry.id)

        if self._is_authorized(guild, config, entry.user):
            return

        await self._punish(guild, config, entry.user, f"{action_desc} en #{channel.name}")


async def setup(bot: commands.Bot):
    await bot.add_cog(SecurityWick(bot))
