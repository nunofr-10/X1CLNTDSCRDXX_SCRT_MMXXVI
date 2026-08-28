import os
import secrets
import hmac
import hashlib
import json
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
    g,
)
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from cryptography.fernet import Fernet, InvalidToken

# ------------------------------------------------------------------
# Entorno de despliegue (separación dev/producción)
# ------------------------------------------------------------------
# APP_ENV distingue el repositorio de pruebas (este mismo código, en tu
# dominio de desarrollo) del dominio dedicado a clientes. Se configura como
# variable de entorno EN CADA despliegue de Vercel por separado:
#   - Despliegue de pruebas (tu dominio actual):     APP_ENV=development
#   - Despliegue de clientes (dominio nuevo/oficial): APP_ENV=production
# No requiere tocar rutas ni el código de negocio: cada despliegue ya lee
# sus propias variables de entorno (DISCORD_REDIRECT_URI, MONGO_URI, etc.)
# de forma independiente. APP_ENV solo activa protecciones adicionales
# (cookies de sesión seguras, debug desactivado, avisos de configuración
# insegura) cuando vale "production".
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"

# app.secret_key SIEMPRE debe quedar configurada antes que cualquier otra
# cosa: Flask la necesita para firmar la cookie de sesión, y sin ella
# CUALQUIER acceso a `session` (incluida la portada "/") lanzaría un
# RuntimeError y tumbaría la página con un 500 antes de llegar a ejecutar
# una sola línea de nuestras vistas.
app = Flask(__name__)
_secret_key = os.environ.get("SECRET_KEY")
if IS_PRODUCTION and not _secret_key:
    print(
        "[ALERTA] APP_ENV=production sin SECRET_KEY configurada -- las "
        "sesiones de los clientes se están firmando con una clave de "
        "desarrollo insegura. Configura SECRET_KEY en las variables de "
        "entorno del despliegue de producción."
    )
app.secret_key = _secret_key or "dev-secret-key"

# En producción, las cookies de sesión deben viajar solo por HTTPS
# (Secure), no ser accesibles desde JavaScript (HttpOnly, ya es el default
# de Flask) y no enviarse en peticiones cross-site (SameSite=Lax). En
# desarrollo local (http://localhost) se dejan como vienen por defecto,
# porque Secure=True bloquearía la cookie sobre HTTP sin TLS.
if IS_PRODUCTION:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

# --- Conexión a MongoDB ---
MONGO_URI = os.environ.get("MONGO_URI")
# Nombre de la base de datos dentro del cluster de Mongo. Por defecto sigue
# siendo "discord_bot" (la instalación original), pero se puede fijar a un
# nombre distinto por entorno -- ej. MONGO_DB_NAME=discord_bot_dev en el
# despliegue de pruebas -- para que dev y producción NUNCA compartan datos
# de clientes reales, incluso si por error apuntaran al mismo cluster.
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "discord_bot")

# La conexión se envuelve en try/except a propósito: si MONGO_URI falta o
# está mal formada, MongoClient(...) puede lanzar una excepción EN EL
# MOMENTO DE IMPORTAR app.py -- eso tumba la aplicación entera (Error 500 en
# TODAS las rutas, incluida "/", antes incluso de que Flask llegue a
# procesar la petición). Si falla, dejamos client/db/las colecciones en None
# y el resto del código las trata como "Mongo no disponible" en lugar de
# crashear.
client = None
db = None
config_collection = None
users_collection = None
settings_collection = None
mongo_init_error = None

try:
    if not MONGO_URI:
        raise PyMongoError("La variable de entorno MONGO_URI no está configurada.")

    client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsAllowInvalidCertificates=True,  # Evita errores SSL/autenticación en Vercel
        serverSelectionTimeoutMS=5000,
    )
    db = client[MONGO_DB_NAME]
    config_collection = db["config"]
    # Colección multi-tenant: mapea el ID de Discord de cada cliente al bot_id
    # que tiene contratado, ej. {"_id": "<discord_user_id>", "bot_id": "<bot_id>"}.
    users_collection = db["users"]
    # Colección GLOBAL (no multi-tenant, no por bot_id) de ajustes exclusivos
    # del propio administrador del SaaS -- ej. las plantillas de embed de los
    # logs de sanciones de Twitch (documento _id="twitch_embed_templates").
    # Los clientes nunca leen ni escriben aquí directamente.
    settings_collection = db["settings"]
    # El webhook de EventSub de Twitch (/webhooks/twitch/eventsub) recibe
    # eventos sin sesión Flask y necesita encontrar, por cada notificación,
    # qué bot/cliente es dueño de ese canal de Twitch -- este índice hace
    # esa búsqueda (find_one({"twitch.broadcaster_id": ...})) rápida incluso
    # con muchos clientes. sparse=True porque la mayoría de documentos
    # todavía no tendrán este campo (clientes que no usan logs de sanciones).
    try:
        config_collection.create_index("twitch.broadcaster_id", sparse=True)
    except Exception as e:
        print(f"[WARN] No se pudo crear el índice twitch.broadcaster_id: {e}")
except Exception as e:
    mongo_init_error = str(e)
    print(f"[WARN] No se pudo inicializar la conexión a MongoDB al arrancar: {e}")


# ------------------------------------------------------------------
# Cifrado de campos sensibles guardados en MongoDB (tokens de bots de
# clientes y cualquier otra credencial que se guarde en el futuro, ej.
# claves de API de Twitch).
#
# ENCRYPTION_KEY es una clave Fernet (AES-128 en modo CBC + HMAC de
# integridad) -- una cadena base64 de 44 caracteres. Genérala UNA VEZ por
# entorno (dev y producción deben tener claves DISTINTAS) con:
#
#     python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
#
# y guárdala como variable de entorno ENCRYPTION_KEY en ese despliegue de
# Vercel. Si se pierde, los valores cifrados con ella ya NO se pueden
# recuperar -- guárdala en un gestor de secretos, no solo en Vercel.
# ------------------------------------------------------------------
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
_fernet = None
if ENCRYPTION_KEY:
    try:
        _fernet = Fernet(ENCRYPTION_KEY.encode())
    except (ValueError, TypeError) as e:
        print(f"[ALERTA] ENCRYPTION_KEY configurada pero no es una clave Fernet válida: {e}")
elif IS_PRODUCTION:
    print(
        "[ALERTA] APP_ENV=production sin ENCRYPTION_KEY configurada -- los "
        "tokens de bots de clientes se guardarán SIN cifrar en MongoDB. "
        "Genera una clave y configúrala antes de dar de alta clientes reales."
    )


def encrypt_secret(value):
    """
    Cifra un valor sensible (ej. bot_token de un cliente) antes de
    guardarlo en MongoDB. Úsalo en TODO punto del código donde se escriba
    un campo sensible a config_collection/users_collection -- nunca guardes
    tokens/credenciales en texto plano.

    Si no hay ENCRYPTION_KEY configurada (típicamente en desarrollo local
    sin la variable puesta), devuelve el valor tal cual con un aviso, para
    no bloquear el trabajo diario -- pero en producción SIEMPRE debe estar
    configurada (ver aviso más arriba).
    """
    if not value:
        return value
    if not _fernet:
        print("[WARN] encrypt_secret(): ENCRYPTION_KEY no configurada, guardando SIN cifrar.")
        return value
    return _fernet.encrypt(value.encode()).decode()


def decrypt_secret(value):
    """
    Descifra un valor guardado con encrypt_secret(). Úsalo en TODO punto
    del código donde se LEA un campo sensible desde MongoDB antes de
    usarlo (ej. al construir el header Authorization para la API de
    Discord).

    Si el valor no está cifrado -- documentos guardados antes de activar
    ENCRYPTION_KEY, o la clave no está configurada -- lo devuelve tal cual
    en vez de lanzar una excepción, para no romper bots ya existentes.
    Ejecuta migrate_encrypt_bot_tokens.py una vez que ENCRYPTION_KEY esté
    configurada, para cifrar los tokens antiguos que queden en texto plano.
    """
    if not value or not _fernet:
        return value
    try:
        return _fernet.decrypt(value.encode()).decode()
    except InvalidToken:
        return value


# ------------------------------------------------------------------
# Registro central de campos sensibles (modelo multi-tenant, extensible)
# ------------------------------------------------------------------
# Cada bot/cliente guarda sus propias credenciales de forma AISLADA en su
# propio documento de config_collection (indexado por bot_id) -- nada de
# esto se comparte entre clientes. Esta lista es solo el CATÁLOGO de qué
# rutas (notación de punto) dentro de ese documento son sensibles y deben
# viajar cifradas con Fernet.
#
# Para añadir un nuevo campo sensible en el futuro (otra integración, una
# API key nueva, un secreto de pago, etc.):
#   1. Añade su ruta aquí.
#   2. Llama a encrypt_secret(valor) en la ruta Flask donde se guarda.
# decrypt_sensitive_fields() ya se encarga de descifrarlo automáticamente
# en CADA get_config() -- no hace falta tocar get_config() de nuevo.
SENSITIVE_CONFIG_PATHS = [
    "bot_token",                            # Token del bot de Discord del cliente
    "twitch.credentials.client_secret",     # Client Secret de la app de Twitch del cliente
    "twitch.access_token",                  # OAuth access_token del streamer (logs de sanciones)
    "twitch.refresh_token",                 # OAuth refresh_token del streamer (logs de sanciones)
]


def _get_by_path(d, path):
    """Lee un valor anidado de un dict a partir de una ruta 'a.b.c'.
    Devuelve None si cualquier tramo del camino no existe o no es un dict."""
    parts = path.split(".")
    cur = d
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _set_by_path(d, path, value):
    """Escribe un valor anidado en un dict a partir de una ruta 'a.b.c',
    creando los sub-diccionarios intermedios que falten."""
    parts = path.split(".")
    cur = d
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def decrypt_sensitive_fields(config):
    """
    Descifra, in-place, TODOS los campos registrados en
    SENSITIVE_CONFIG_PATHS que estén presentes en `config` (el documento de
    un bot/cliente concreto, ya fusionado con sus defaults). Se llama una
    única vez al final de get_config() -- así cada campo sensible nuevo que
    se añada al registro se descifra automáticamente para TODO el código
    que llama a get_config(), sin tener que acordarse de tocarlo aquí cada
    vez.
    """
    for path in SENSITIVE_CONFIG_PATHS:
        value = _get_by_path(config, path)
        if value:
            _set_by_path(config, path, decrypt_secret(value))
    return config


def mongo_ready():
    """True si la conexión a MongoDB se inicializó correctamente al arrancar
    la app. Úsalo antes de cualquier operación sobre config_collection /
    users_collection que no pase ya por get_config()/save_fields()."""
    return config_collection is not None and users_collection is not None


# Documento único que guarda la configuración actual del bot
CONFIG_ID = "bot_config"

# ------------------------------------------------------------------
# SaaS Multitenant: administración y licenciamiento de módulos
# ------------------------------------------------------------------
# ID de Discord del propietario/administrador del SaaS. Tiene acceso a
# /admin y, por defecto (sin estar simulando a ningún cliente), usa su
# propio bot de prueba/personal.
ADMIN_DISCORD_ID = os.environ.get("ADMIN_DISCORD_ID", "TU_ID_DE_DISCORD_AQUI")

# bot_id del bot personal del admin. Usa a propósito el mismo _id que el
# documento singleton original ("bot_config") para que la instalación
# existente se convierta automáticamente en "el bot #1" del sistema
# multi-tenant, sin necesidad de migrar datos.
ADMIN_PERSONAL_BOT_ID = os.environ.get("ADMIN_PERSONAL_BOT_ID", CONFIG_ID)

# Módulos licenciables individualmente por cliente desde el Panel de
# Administración (config['allowed_modules']).
LICENSABLE_MODULES = [
    {"key": "tickets", "label": "Tickets"},
    {"key": "moderation", "label": "Moderación"},
    {"key": "youtube", "label": "YouTube"},
    {"key": "twitch", "label": "Twitch"},
    {"key": "twitch_logs", "label": "Logs Twitch"},
    {"key": "wick_security", "label": "Anti-Raid (BETA)"},
]

# ------------------------------------------------------------------
# Credenciales de Discord. Deben configurarse como variables de entorno:
#   DISCORD_CLIENT_ID      -> ID de la aplicación (OAuth2)
#   DISCORD_CLIENT_SECRET  -> Secreto de la aplicación (OAuth2)
#   DISCORD_BOT_TOKEN      -> Token del bot (para leer canales/roles del servidor)
#   DISCORD_REDIRECT_URI   -> URL de callback registrada en el portal de Discord,
#                              ej. https://tu-dashboard.vercel.app/callback
# ------------------------------------------------------------------
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "http://localhost:5000/callback")

DISCORD_API = "https://discord.com/api"
PERM_ADMINISTRATOR = 0x8
PERM_MANAGE_GUILD = 0x20

# ------------------------------------------------------------------
# Logs de sanciones de Twitch en tiempo real (EventSub). Variables de
# entorno GLOBALES de la plataforma (una sola vez, no por cliente):
#   TWITCH_OAUTH_REDIRECT_URI  -> URL de callback de /twitch/oauth/callback,
#                                  ej. https://tu-dashboard.com/twitch/oauth/callback.
#                                  Se registra en el campo "OAuth Redirect URLs"
#                                  de la app de Twitch de CADA cliente (todas
#                                  pueden compartir la misma URL fija).
#   TWITCH_EVENTSUB_CALLBACK_URL -> URL pública donde Twitch envía las
#                                  notificaciones de sanciones, ej.
#                                  https://tu-dashboard.com/webhooks/twitch/eventsub.
#                                  Debe ser HTTPS y accesible desde internet
#                                  (Twitch la verifica con un "challenge" al
#                                  crear cada suscripción).
#   TWITCH_EVENTSUB_SECRET     -> secreto compartido para firmar/verificar
#                                  los webhooks (HMAC-SHA256). Genera uno
#                                  aleatorio largo (ej. `openssl rand -hex 32`)
#                                  y NO lo publiques -- es el mismo para
#                                  todos los clientes, ya que cada evento ya
#                                  se identifica y aísla por broadcaster_id.
#
# Cada CLIENTE, además, usa su propio Client ID/Secret de Twitch (guardados
# cifrados en twitch.credentials, ver DEFAULT_TWITCH_CREDENTIALS) -- esas NO
# son variables de entorno globales, se configuran desde /twitch en el panel.
# ------------------------------------------------------------------
TWITCH_OAUTH_REDIRECT_URI = os.environ.get(
    "TWITCH_OAUTH_REDIRECT_URI", "http://localhost:5000/twitch/oauth/callback"
)
TWITCH_EVENTSUB_CALLBACK_URL = os.environ.get(
    "TWITCH_EVENTSUB_CALLBACK_URL", "http://localhost:5000/webhooks/twitch/eventsub"
)
TWITCH_EVENTSUB_SECRET = os.environ.get("TWITCH_EVENTSUB_SECRET")

TWITCH_AUTH_API = "https://id.twitch.tv/oauth2"
TWITCH_HELIX_API = "https://api.twitch.tv/helix"

# Scopes que el streamer debe autorizar para que la plataforma pueda crear
# las 3 suscripciones EventSub de sanciones (ban/timeout, advertencias,
# mensajes borrados). Si Twitch cambia estos requisitos en el futuro,
# revisa https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/
# antes de tocar esta lista.
TWITCH_OAUTH_SCOPES = [
    "channel:moderate",              # channel.ban (bans y timeouts)
    "moderator:manage:warnings",     # channel.warning.send (advertencias)
    "user:read:chat",                # channel.chat.message_delete (borrados) -- lado "chatting user"
    "user:bot",                      # channel.chat.message_delete -- exigido además de user:read:chat
                                      # cuando la suscripción se crea con un App Access Token (nuestro caso)
    "channel:bot",                   # channel.chat.message_delete -- lado broadcaster (alternativa a ser moderador)
    "user:read:moderated_channels",  # listar los canales que el usuario modera (selector de canal)
]

# Tipos de suscripción EventSub que crea /twitch/oauth/callback, y a qué
# filtro de config.twitch.filters corresponde cada uno. "delete_message" y
# "warning"/"ban"/"timeout" se resuelven en el propio payload del evento
# (ver handle_twitch_eventsub_notification()).
TWITCH_EVENTSUB_SUBSCRIPTIONS = [
    {"type": "channel.ban", "version": "1"},
    {"type": "channel.warning.send", "version": "1"},
    {"type": "channel.chat.message_delete", "version": "1"},
]

# Valores permitidos para el tipo de mensaje del panel de tickets
MESSAGE_TYPES = {
    "embed": "Embed con diseño",
    "text": "Texto normal",
}

# Variables dinámicas que el bot reemplaza al enviar el panel en Discord
AVAILABLE_VARIABLES = [
    {"token": "{user}", "label": "Mención al usuario"},
    {"token": "{user.mention}", "label": "Mención al usuario"},
    {"token": "{user.name}", "label": "Nombre del usuario"},
    {"token": "{server}", "label": "Nombre del servidor"},
    {"token": "{server.members}", "label": "Cantidad de miembros"},
    {"token": "{channel}", "label": "Canal actual"},
]

# Variables dinámicas disponibles en el módulo de YouTube (vídeos / directos).
YOUTUBE_VARIABLES = [
    {"token": "{title}", "label": "Título del vídeo/directo"},
    {"token": "{author}", "label": "Nombre del canal de YouTube"},
    {"token": "{url}", "label": "Enlace al vídeo/directo"},
]

# Variables dinámicas disponibles en el módulo de Twitch (directos).
TWITCH_VARIABLES = [
    {"token": "{title}", "label": "Título del directo"},
    {"token": "{author}", "label": "Nombre del canal de Twitch"},
    {"token": "{url}", "label": "Enlace al directo"},
]

DEFAULT_EMBED = {
    "author": "",
    "title": "",
    "description": "",
    "footer": "",
    "image_url": "",
    "thumbnail_url": "",
    "color": "#5865f2",
}

# Mensaje que se envía dentro del canal privado al abrirse un ticket
DEFAULT_WELCOME = {
    "tipo_mensaje": "embed",
    "mensaje": "",
    "embed": dict(DEFAULT_EMBED),
}

# ------------------------------------------------------------------
# Defaults del módulo de YouTube (notificaciones de vídeos y directos)
# ------------------------------------------------------------------
DEFAULT_YOUTUBE_VIDEOS = {
    "enabled": True,
    "channel_id": "",
    "discord_channel_id": "",
    "ping_role_id": "",
    "mensaje": "🎬 ¡Nuevo vídeo! {title} - {url}",
    # Dentro de "enabled" (el interruptor general de la sección) se puede
    # además elegir por separado si avisar de vídeos normales y/o de
    # Shorts -- el bot detecta el tipo de cada subida nueva y filtra según
    # estos dos toggles antes de enviar el aviso a Discord.
    "notify_videos": True,
    "notify_shorts": True,
}

DEFAULT_YOUTUBE_STREAMS = {
    "enabled": True,
    "channel_id": "",
    "discord_channel_id": "",
    "ping_role_id": "",
    "mensaje": "🔴 ¡Estamos en directo! {title} - {url}",
}

DEFAULT_YOUTUBE_CONFIG = {
    # IDs de vídeos/directos ya notificados, para que el bot no repita el
    # aviso. Es estado gestionado por el bot, no por el dashboard: al
    # guardar desde la web (save_youtube) nunca se sobrescribe este campo.
    "notified_ids": [],
    "videos": dict(DEFAULT_YOUTUBE_VIDEOS),
    "streams": dict(DEFAULT_YOUTUBE_STREAMS),
}

# ------------------------------------------------------------------
# Defaults del módulo de Twitch (notificaciones de directos)
# ------------------------------------------------------------------
DEFAULT_TWITCH_LIVE = {
    "enabled": True,
    # URL completa (https://www.twitch.tv/tu_canal) o nombre de usuario
    # (tu_canal), tal cual lo escriba el usuario. El bot se encarga de
    # normalizarlo y extraer el nombre de canal real antes de consultar la
    # API de Twitch -- el dashboard nunca lo parsea ni lo valida.
    "channel": "",
    "discord_channel_id": "",
    "ping_role_id": "",
    "mensaje": "🔴 ¡{author} está en directo! {title} - {url}",
}

# Credenciales de la app de Twitch del propio cliente (Twitch Developer
# Console). Cada bot/cliente puede usar su propia app de Twitch en vez de
# depender de una app global compartida -- aislamiento total, como con
# bot_token. "client_secret" viaja cifrado con Fernet (ver
# SENSITIVE_CONFIG_PATHS); "client_id" no es secreto (es análogo a
# discord_user_id/client_id de Discord) y se guarda tal cual.
DEFAULT_TWITCH_CREDENTIALS = {
    "client_id": "",
    "client_secret": "",
}

# ------------------------------------------------------------------
# Logs de sanciones de Twitch en tiempo real (EventSub) -- campos fijos
# dentro del propio documento "twitch" del cliente, aislados igual que el
# resto del módulo:
#   - broadcaster_id: ID numérico del canal de Twitch del cliente (lo
#     devuelve la API de Twitch al vincular la cuenta, GET /helix/users).
#   - access_token/refresh_token: tokens OAuth del propio streamer,
#     obtenidos en /twitch/oauth/callback. Viajan cifrados con Fernet
#     (ver SENSITIVE_CONFIG_PATHS) -- se usan para demostrar ante Twitch
#     que el streamer autorizó los scopes de moderación; las suscripciones
#     EventSub en sí se crean con un App Access Token (client credentials
#     de twitch.credentials), no con estos tokens de usuario.
#   - log_channel_id: canal de Discord del cliente donde se publican los
#     avisos de sanciones.
#   - filters: qué tipos de sanción quiere recibir este cliente. El
#     webhook los consulta ANTES de enviar cualquier aviso a Discord.
#   - subscription_ids: bookkeeping interno (ids de las suscripciones
#     EventSub ya creadas en Twitch), para poder depurarlas/revisarlas
#     sin tener que volver a listarlas desde la API cada vez.
DEFAULT_TWITCH_FILTERS = {
    "ban": True,
    "timeout": True,
    "warning": True,
    "delete_message": True,
}

DEFAULT_TWITCH_CONFIG = {
    # IDs de directos ya notificados, para que el bot no repita el aviso.
    # Es estado gestionado por el bot, no por el dashboard: al guardar
    # desde la web (save_twitch) nunca se sobrescribe este campo.
    "notified_ids": [],
    "live": dict(DEFAULT_TWITCH_LIVE),
    "credentials": dict(DEFAULT_TWITCH_CREDENTIALS),
    "broadcaster_id": "",
    "broadcaster_login": "",
    "broadcaster_display_name": "",
    # ID/login de la cuenta de Twitch que hizo login por OAuth (la que
    # realmente concedió los scopes a nuestra app). Es SIEMPRE la primera
    # entrada de available_channels ("propio canal"). Es distinta de
    # broadcaster_id cuando el cliente elige monitorizar un canal que
    # modera en vez del suyo propio -- Twitch exige usar este ID (y no el
    # del canal elegido) como moderator_user_id/user_id al crear las
    # suscripciones EventSub, porque la autorización la dio esta cuenta.
    "linked_user_id": "",
    "linked_login": "",
    # Canales candidatos a monitorizar: el propio canal del streamer + los
    # canales donde su cuenta es moderadora (GET /helix/moderation/channels).
    # Se recalcula cada vez que (re)vincula la cuenta; alimenta el
    # desplegable de selección de canal en Logs Twitch.
    "available_channels": [],
    "access_token": "",
    "refresh_token": "",
    "log_channel_id": "",
    "filters": dict(DEFAULT_TWITCH_FILTERS),
    "subscription_ids": {},
}

# ------------------------------------------------------------------
# Defaults del sistema de Seguridad Profesional "WickSecurity"
# (AutoMod, AntiNuke, Cuarentena, JoinGate, Whitelists), estilo WickBot.
# ------------------------------------------------------------------
JOINGATE_ACTIONS = {
    "kick": "Expulsar (Kick)",
    "ban": "Banear (Ban)",
}

DEFAULT_MISC_CONFIG = {
    "log_channel_id": "",
    "mod_log_channel_id": "",
    "main_role_id": "",
}

DEFAULT_ANTISPAM_CONFIG = {
    "enabled": True,
    "mention_spam": True,
    "attachment_spam": True,
    "repetitive_spam": True,
    "long_messages": True,
    "emoji_spam": True,
    "new_lines_spam": True,
    "zalgo_spam": True,
}

DEFAULT_AUTOMOD_CONFIG = {
    "enabled": True,
    "moderate_invites": True,
    "filter_nsfw": True,
    "filter_scam": True,
    "anti_spam": dict(DEFAULT_ANTISPAM_CONFIG),
    "monitor_webhooks": True,
}

DEFAULT_ANTINUKE_CONFIG = {
    "enabled": True,
    "monitor_kicks_bans": True,
    "monitor_role_creates": True,
    "monitor_role_deletes": True,
    "monitor_channel_creates": True,
    "monitor_channel_deletes": True,
    "monitor_webhook_creates": True,
    "monitor_webhook_deletes": True,
}

DEFAULT_QUARANTINE_CONFIG = {
    "enabled": True,
    "punish_unauthorized_admins_perms": True,
    "punish_unauthorized_admins_members": True,
    "protect_everyone_main_roles": True,
    "guard_vanity_url": True,
    "quarantine_role_id": "",
}

DEFAULT_JOINGATE_CONFIG = {
    "enabled": True,
    "target_unauthorized_bots": True,
    "target_young_accounts": True,
    "min_account_age_hours": 24,
    "target_no_pfp": True,
    "target_unverified_bots": True,
    "target_invite_in_name": True,
    "target_suspicious_nicks": True,
    "action": "kick",
}

# Cada "grupo" de whitelist admite 5 tipos de entidad. members/webhooks se
# gestionan como listas de IDs escritas a mano (el dashboard no tiene forma
# de listar los miembros/webhooks reales de un servidor vía API sin
# intents/permiso adicionales); roles/channels/categories sí se seleccionan
# desde selects reales alimentados por la API de Discord.
DEFAULT_WHITELIST_GROUP = {
    "members": [],
    "roles": [],
    "channels": [],
    "categories": [],
    "webhooks": [],
}

DEFAULT_WHITELISTS_CONFIG = {
    "spam": dict(DEFAULT_WHITELIST_GROUP),
    "invites": dict(DEFAULT_WHITELIST_GROUP),
    "pings": dict(DEFAULT_WHITELIST_GROUP),
    "everyone": dict(DEFAULT_WHITELIST_GROUP),
    "channel_creation_categories": [],
    "quarantine_users": [],
}

# Comandos slash del módulo de Moderación, con activación y roles autorizados
# configurables de forma individual desde el dashboard.
MODERATION_COMMANDS = [
    {"key": "warn", "label": "/warn", "description": "Advierte a un usuario y registra el motivo."},
    {"key": "warns", "label": "/warns", "description": "Muestra el historial de advertencias de un usuario."},
    {"key": "clear-warns", "label": "/clear-warns", "description": "Elimina las advertencias guardadas de un usuario."},
    {"key": "mute", "label": "/mute", "description": "Aplica un timeout (silencio) a un usuario."},
    {"key": "unmute", "label": "/unmute", "description": "Remueve el timeout de un usuario."},
    {"key": "kick", "label": "/kick", "description": "Expulsa a un usuario del servidor."},
    {"key": "ban", "label": "/ban", "description": "Banea a un usuario del servidor."},
    {"key": "clear", "label": "/clear", "description": "Purga hasta 100 mensajes del canal actual."},
]

DEFAULT_CONFIG = {
    "_id": CONFIG_ID,
    "guild_id": "",
    # --- Metadatos SaaS multi-tenant (uno por cada bot/cliente) ---
    "bot_name": "",
    "discord_user_id": "",
    "bot_token": "",
    "client_id": "",
    # Licencia: qué módulos tiene contratados este bot/cliente. Se controla
    # desde el Panel de Administración (/admin). Por defecto todo permitido,
    # así el bot del admin y las instalaciones ya existentes siguen
    # funcionando igual sin necesidad de migrar datos.
    "allowed_modules": {
        "tickets": True,
        "moderation": True,
        "youtube": True,
        "twitch": True,
        # Módulo independiente de Twitch (no depende de "twitch"): logs de
        # sanciones en tiempo real vía EventSub. Tiene su propia tarjeta,
        # su propio candado de licencia y su propia página (/twitch/logs) --
        # solo comparte con "twitch" el Client ID/Secret de la app de Twitch
        # del cliente, que es infraestructura técnica, no licencia.
        "twitch_logs": True,
        # Licencia única que cubre TODO el sistema Anti-Raid / WickSecurity
        # (AutoMod, AntiNuke, Cuarentena y JoinGate comparten un solo
        # candado/página).
        "wick_security": True,
    },
    # Estado global de encendido/apagado de cada módulo completo. Es la fuente
    # de verdad tanto para el dashboard como para el bot (ver cogs/moderation.py).
    "modules": {
        "tickets": True,
        "moderation": True,
        "youtube": True,
        "twitch": True,
        "twitch_logs": True,
        # Switch maestro del sistema Anti-Raid / WickSecurity completo
        # (tarjeta propia en modules.html, licenciado como un único bloque
        # -- ver allowed_modules.wick_security).
        "wick_security": True,
        # Switches independientes de los 4 submódulos de Anti-Raid, cada uno
        # controlado desde su propio paso en wick_security.html y
        # sincronizado con su "enabled" anidado (ver save_wick_automod() etc).
        # No tienen tarjeta propia en modules.html: el bot debe comprobar
        # SIEMPRE modules.wick_security Y el submódulo concreto antes de
        # actuar (ej. modules.wick_security and modules.automod).
        "automod": True,
        "antinuke": True,
        "joingate": True,
        "quarantine": True,
    },
    "tipo_mensaje": "embed",
    "mensaje": "",
    "embed": dict(DEFAULT_EMBED),
    "mensaje_bienvenida": dict(DEFAULT_WELCOME),
    "canal_id": "",
    "categoria_id": "",
    "staff_roles": [],
    "features": {
        "close": True,
        "claim": True,
        "transcript": True,
        "transcript_channel_id": "",
        "add_remove_users": True,
    },
    "mod_log_channel_id": "",
    "commands": {
        cmd["key"]: {"enabled": True, "roles": []} for cmd in MODERATION_COMMANDS
    },
    "youtube": dict(DEFAULT_YOUTUBE_CONFIG),
    "twitch": dict(DEFAULT_TWITCH_CONFIG),
    # --- Sistema de Seguridad Profesional Anti-Raid (BETA) "WickSecurity" ---
    "misc": dict(DEFAULT_MISC_CONFIG),
    "automod": dict(DEFAULT_AUTOMOD_CONFIG),
    "antinuke": dict(DEFAULT_ANTINUKE_CONFIG),
    "quarantine": dict(DEFAULT_QUARANTINE_CONFIG),
    "joingate": dict(DEFAULT_JOINGATE_CONFIG),
    "whitelists": dict(DEFAULT_WHITELISTS_CONFIG),
}

TICKETS_MODULE = {
    "id": "tickets",
    "name": "Tickets",
    "badge": "Nuevo",
    "description": "Tickets de soporte con panel desplegable desde el dashboard, "
    "canales privados, transcripts y acciones de staff.",
}

MODERATION_MODULE = {
    "id": "moderacion",
    "name": "Moderación",
    "badge": "Nuevo",
    "description": "Comandos de moderación (warn, mute, kick, ban, clear) con roles de "
    "staff y registro de sanciones en un canal de logs.",
}

YOUTUBE_MODULE = {
    "id": "youtube",
    "name": "YouTube",
    "badge": "Nuevo",
    "description": "Notificaciones automáticas en Discord cuando subes un vídeo nuevo o "
    "empiezas un directo en YouTube.",
}

TWITCH_MODULE = {
    "id": "twitch",
    "name": "Twitch",
    "badge": "Nuevo",
    "description": "Notificación automática en Discord en cuanto tu canal de Twitch "
    "se pone en directo.",
}

# Módulo independiente de "Twitch" (notificaciones de directo) -- licencia,
# tarjeta y candado propios. Solo comparte con "twitch" el Client ID/Secret
# de la app de Twitch del cliente (infraestructura técnica), nunca el
# estado de encendido/apagado ni la licencia.
TWITCH_LOGS_MODULE = {
    "id": "twitch_logs",
    "name": "Logs Twitch",
    "badge": "Nuevo",
    "description": "Avisos en Discord en tiempo real de baneos, timeouts, advertencias "
    "y mensajes borrados por los moderadores de tu canal de Twitch.",
}

WICK_SECURITY_MODULE = {
    "id": "wick_security",
    "name": "Anti-Raid",
    "badge": "BETA",
    "description": "Sistema profesional de seguridad: AutoMod, AntiNuke, Cuarentena y "
    "JoinGate con listas blancas, asistente por pasos y previsualización de chat.",
}


# ------------------------------------------------------------------
# Helpers de MongoDB
# ------------------------------------------------------------------
def _dict_field(source, key):
    """
    Devuelve source.get(key) SOLO si es un dict; en cualquier otro caso
    (None, string, list, número, o si falta) devuelve {}.

    Protege el merge de get_config() contra documentos antiguos o corruptos
    en MongoDB donde un campo que debería ser un objeto anidado (ej.
    "welcome", "youtube", "modules") terminó guardado con otra forma. Sin
    esto, un simple `.get()` sobre ese valor lanzaría AttributeError y
    tumbaría CUALQUIER página que dependa de get_config() -- incluida la
    portada de Módulos.
    """
    value = source.get(key)
    return value if isinstance(value, dict) else {}


def is_user_blocked(discord_user_id):
    """
    True si el administrador ha bloqueado explícitamente el acceso de este
    ID de Discord (users_collection[discord_user_id]['blocked'] == True).

    El admin del SaaS (ADMIN_DISCORD_ID) nunca puede quedar bloqueado por
    esta comprobación -- evita que el propio dueño se encierre fuera del
    sistema por error.

    El resultado se cachea en `g` (memoria del request actual) para que
    current_bot_id() -- que se llama muchas veces por request, desde
    get_config(), save_fields() y los decoradores de acceso -- no dispare
    una consulta a MongoDB por cada llamada. Aun así, se vuelve a consultar
    en CADA request nuevo, así que un bloqueo aplicado por el admin surte
    efecto de inmediato, sin esperar a que el cliente cierre sesión y
    vuelva a entrar.
    """
    if not discord_user_id or discord_user_id == ADMIN_DISCORD_ID or not mongo_ready():
        return False

    cache = getattr(g, "_blocked_users_cache", None)
    if cache is None:
        cache = {}
        g._blocked_users_cache = cache
    if discord_user_id in cache:
        return cache[discord_user_id]

    try:
        user_doc = users_collection.find_one({"_id": discord_user_id}, {"blocked": 1})
    except PyMongoError as e:
        print(f"[WARN] is_user_blocked(): {e}")
        cache[discord_user_id] = False
        return False

    blocked = bool(user_doc and user_doc.get("blocked"))
    cache[discord_user_id] = blocked
    return blocked


def current_bot_id():
    """
    bot_id activo de la sesión actual (SaaS multi-tenant).

    Es el _id del documento en config_collection que get_config()/save_fields()
    deben leer y escribir. Se resuelve así para que la inmensa mayoría de las
    llamadas existentes a get_config()/save_fields() en el resto del archivo
    no necesiten cambiar: internamente ambas funciones consultan este valor
    en vez de recibir un parámetro bot_id explícito.

    - Cliente normal logueado: su bot_id (guardado en users_collection).
    - Admin sin simular a nadie: ADMIN_PERSONAL_BOT_ID (su propio bot).
    - Admin simulando a un cliente: el bot_id de ese cliente.
    - Nadie logueado / sin bot asignado: None.
    - Cliente bloqueado por el admin: SIEMPRE None, aunque su sesión
      todavía tenga guardado un active_bot_id de antes de ser bloqueado --
      esto es lo que hace que el bloqueo cierre el acceso al instante en
      cualquier ruta protegida (requires_login/requires_module/index()),
      sin depender de que el cliente vuelva a loguearse.
    """
    user = current_user()
    if user and is_user_blocked(str(user.get("id", ""))):
        return None
    return session.get("active_bot_id")


def is_admin():
    """True si el usuario logueado es el propietario/administrador del SaaS."""
    user = current_user()
    return bool(user) and str(user.get("id", "")) == ADMIN_DISCORD_ID


def modulo_permitido(config, key):
    """True si el bot/cliente activo tiene contratado (licenciado) el módulo `key`."""
    allowed = config.get("allowed_modules")
    if not isinstance(allowed, dict):
        return True
    return bool(allowed.get(key, True))


def active_bot_token(config):
    """Token de bot a usar para llamar a la API de Discord: el del bot/cliente
    activo si está guardado, o el token global (DISCORD_BOT_TOKEN) como
    respaldo -- así el bot personal del admin sigue funcionando sin tener
    que rellenar bot_token manualmente."""
    return config.get("bot_token") or DISCORD_BOT_TOKEN


def get_config(bot_id=None):
    """
    Obtiene la configuración de un bot/cliente desde MongoDB, rellenando
    defaults.

    Por defecto usa el bot/cliente activo de la sesión Flask actual
    (bot_id = current_bot_id()) -- así el 99% de las llamadas existentes en
    el dashboard no necesitan cambiar. Pasar `bot_id` explícitamente permite
    leer la config de un cliente concreto SIN sesión Flask, que es lo que
    necesita el webhook de EventSub de Twitch (/webhooks/twitch/eventsub):
    Twitch nos llama directamente, sin cookie de sesión, así que el bot_id
    se resuelve buscando en Mongo qué cliente tiene ese "twitch.broadcaster_id"
    y se pasa aquí a mano.

    Si no hay ningún bot activo/indicado, devuelve DEFAULT_CONFIG tal cual
    -- las vistas que dependen de un bot real deben comprobar
    current_bot_id() / current_user() antes de fiarse de que esta config
    corresponde a un cliente de verdad.
    """
    bot_id = bot_id or current_bot_id()
    if not bot_id:
        return dict(DEFAULT_CONFIG)

    if not mongo_ready():
        # MongoDB no se pudo inicializar al arrancar (MONGO_URI ausente/mala,
        # sin red, etc.) -- no intentamos siquiera consultar config_collection
        # (sería None y lanzaría AttributeError). safe_get_config() es quien
        # debe avisar al usuario; aquí simplemente devolvemos defaults.
        return {**dict(DEFAULT_CONFIG), "_id": bot_id}

    config = config_collection.find_one({"_id": bot_id})
    if config is None:
        return {**dict(DEFAULT_CONFIG), "_id": bot_id}

    if not isinstance(config, dict):
        # Nunca debería pasar, pero si el documento en Mongo está corrupto
        # de alguna forma inesperada, no arriesgamos un crash aquí.
        return {**dict(DEFAULT_CONFIG), "_id": bot_id}

    merged = dict(DEFAULT_CONFIG)
    merged.update(config)
    merged["_id"] = bot_id

    merged["allowed_modules"] = {
        **DEFAULT_CONFIG["allowed_modules"],
        **_dict_field(config, "allowed_modules"),
    }

    # Estado de módulos (config.modules.tickets / config.modules.moderation).
    # Compatibilidad con documentos antiguos que todavía tengan los campos
    # planos tickets_enabled / moderation_enabled de antes de introducir
    # el bloque "modules".
    modules = dict(DEFAULT_CONFIG["modules"])
    if "tickets_enabled" in config:
        modules["tickets"] = bool(config["tickets_enabled"])
    if "moderation_enabled" in config:
        modules["moderation"] = bool(config["moderation_enabled"])
    modules.update(_dict_field(config, "modules"))
    merged["modules"] = modules

    merged["embed"] = {**DEFAULT_EMBED, **_dict_field(config, "embed")}
    merged["features"] = {**DEFAULT_CONFIG["features"], **_dict_field(config, "features")}

    welcome_msg = {**DEFAULT_WELCOME, **_dict_field(config, "mensaje_bienvenida")}
    welcome_msg["embed"] = {**DEFAULT_EMBED, **_dict_field(welcome_msg, "embed")}
    merged["mensaje_bienvenida"] = welcome_msg

    # Merge profundo de config.commands: cada comando conserva sus defaults
    # (enabled=True, roles=[]) si no está guardado todavía en MongoDB.
    stored_commands = _dict_field(config, "commands")
    commands = {}
    for key, default_cmd in DEFAULT_CONFIG["commands"].items():
        commands[key] = {**default_cmd, **_dict_field(stored_commands, key)}
    merged["commands"] = commands

    # Merge profundo del módulo de YouTube: "videos" y "streams" conservan
    # sus defaults campo a campo; "notified_ids" es estado gestionado por el
    # bot y se conserva tal cual esté guardado (nunca se resetea aquí).
    stored_youtube = _dict_field(config, "youtube")
    notified_ids = stored_youtube.get("notified_ids")
    merged["youtube"] = {
        "notified_ids": list(notified_ids) if isinstance(notified_ids, list) else [],
        "videos": {**DEFAULT_YOUTUBE_VIDEOS, **_dict_field(stored_youtube, "videos")},
        "streams": {**DEFAULT_YOUTUBE_STREAMS, **_dict_field(stored_youtube, "streams")},
    }

    # Merge profundo del módulo de Twitch: "live" y "credentials" conservan
    # sus defaults campo a campo; "notified_ids" es estado gestionado por el
    # bot y se conserva tal cual esté guardado (nunca se resetea aquí).
    # "credentials.client_secret" todavía está cifrado en este punto -- se
    # descifra más abajo junto al resto de SENSITIVE_CONFIG_PATHS.
    stored_twitch = _dict_field(config, "twitch")
    twitch_notified_ids = stored_twitch.get("notified_ids")
    stored_twitch_subscription_ids = stored_twitch.get("subscription_ids")
    merged["twitch"] = {
        "notified_ids": list(twitch_notified_ids) if isinstance(twitch_notified_ids, list) else [],
        "live": {**DEFAULT_TWITCH_LIVE, **_dict_field(stored_twitch, "live")},
        "credentials": {
            **DEFAULT_TWITCH_CREDENTIALS,
            **_dict_field(stored_twitch, "credentials"),
        },
        # Logs de sanciones (EventSub). "access_token"/"refresh_token"
        # todavía están cifrados en este punto -- se descifran más abajo
        # junto al resto de SENSITIVE_CONFIG_PATHS.
        "broadcaster_id": stored_twitch.get("broadcaster_id") or "",
        "broadcaster_login": stored_twitch.get("broadcaster_login") or "",
        "broadcaster_display_name": stored_twitch.get("broadcaster_display_name") or "",
        "linked_user_id": stored_twitch.get("linked_user_id") or "",
        "linked_login": stored_twitch.get("linked_login") or "",
        "available_channels": (
            list(stored_twitch.get("available_channels"))
            if isinstance(stored_twitch.get("available_channels"), list)
            else []
        ),
        "access_token": stored_twitch.get("access_token") or "",
        "refresh_token": stored_twitch.get("refresh_token") or "",
        "log_channel_id": stored_twitch.get("log_channel_id") or "",
        "filters": {**DEFAULT_TWITCH_FILTERS, **_dict_field(stored_twitch, "filters")},
        "subscription_ids": (
            dict(stored_twitch_subscription_ids)
            if isinstance(stored_twitch_subscription_ids, dict)
            else {}
        ),
    }

    # ----------------------------------------------------------------
    # Merge profundo del sistema Anti-Raid "WickSecurity" (misc, automod,
    # antinuke, cuarentena, joingate, whitelists). modules.X es siempre la
    # fuente de verdad: cada bloque X.enabled se sincroniza a partir de
    # modules.X DESPUÉS del merge.
    # ----------------------------------------------------------------
    merged["misc"] = {**DEFAULT_MISC_CONFIG, **_dict_field(config, "misc")}

    stored_automod = _dict_field(config, "automod")
    automod = {**DEFAULT_AUTOMOD_CONFIG, **stored_automod}
    automod["anti_spam"] = {**DEFAULT_ANTISPAM_CONFIG, **_dict_field(stored_automod, "anti_spam")}
    merged["automod"] = automod

    merged["antinuke"] = {**DEFAULT_ANTINUKE_CONFIG, **_dict_field(config, "antinuke")}
    merged["quarantine"] = {**DEFAULT_QUARANTINE_CONFIG, **_dict_field(config, "quarantine")}

    joingate = {**DEFAULT_JOINGATE_CONFIG, **_dict_field(config, "joingate")}
    if joingate.get("action") not in JOINGATE_ACTIONS:
        joingate["action"] = DEFAULT_JOINGATE_CONFIG["action"]
    merged["joingate"] = joingate

    def _merge_whitelist_group(stored_group):
        group = dict(DEFAULT_WHITELIST_GROUP)
        stored_group = stored_group if isinstance(stored_group, dict) else {}
        for entity_type in DEFAULT_WHITELIST_GROUP:
            raw_list = stored_group.get(entity_type)
            group[entity_type] = [str(v) for v in raw_list] if isinstance(raw_list, list) else []
        return group

    stored_whitelists = _dict_field(config, "whitelists")
    whitelists = {}
    for group_name in ("spam", "invites", "pings", "everyone"):
        whitelists[group_name] = _merge_whitelist_group(stored_whitelists.get(group_name))

    for flat_list_name in ("channel_creation_categories", "quarantine_users"):
        raw_list = stored_whitelists.get(flat_list_name)
        whitelists[flat_list_name] = [str(v) for v in raw_list] if isinstance(raw_list, list) else []

    merged["whitelists"] = whitelists

    for module_key, config_key in (
        ("automod", "automod"),
        ("antinuke", "antinuke"),
        ("quarantine", "quarantine"),
        ("joingate", "joingate"),
    ):
        merged["modules"][module_key] = bool(
            merged["modules"].get(module_key, True)
        )
        merged[config_key]["enabled"] = merged["modules"][module_key]

    # Descifra TODOS los campos sensibles registrados en
    # SENSITIVE_CONFIG_PATHS (bot_token, twitch.credentials.client_secret,
    # y cualquiera que se añada en el futuro) justo antes de devolver la
    # config -- así el resto del código (active_bot_token(), la llamada a
    # la API de Twitch, etc.) sigue recibiendo los valores en texto plano
    # listos para usar, para ESTE bot/cliente exclusivamente, sin mezclarse
    # con los de ningún otro.
    decrypt_sensitive_fields(merged)

    return merged


def save_fields(fields):
    """
    Actualiza únicamente los campos indicados en el documento del bot/cliente
    activo de la sesión (bot_id = current_bot_id()).

    Lanza PyMongoError (nunca AttributeError/TypeError) tanto si no hay bot
    activo como si Mongo no está disponible, para que todo el código que ya
    hace `except PyMongoError` alrededor de save_fields(...) siga
    funcionando sin cambios.
    """
    bot_id = current_bot_id()
    if not bot_id:
        raise PyMongoError("No hay ningún bot activo en la sesión.")
    if not mongo_ready():
        raise PyMongoError("La conexión a MongoDB no está disponible.")
    config_collection.update_one({"_id": bot_id}, {"$set": fields}, upsert=True)


# ------------------------------------------------------------------
# Helpers de la API de Discord
# ------------------------------------------------------------------
def discord_get(endpoint, token=None, use_bot=False, bot_token=None):
    headers = {}
    if use_bot:
        headers["Authorization"] = f"Bot {bot_token or DISCORD_BOT_TOKEN}"
    elif token:
        headers["Authorization"] = f"Bearer {token}"

    resp = requests.get(f"{DISCORD_API}{endpoint}", headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def fetch_guild_channels(guild_id, bot_token, types=None):
    """
    Devuelve los canales de un servidor, opcionalmente filtrados por tipo
    (0=texto, 4=categoría, 5=anuncios...), usando el token del bot/cliente
    activo (bot_token) -- cada bot del SaaS solo puede leer los canales del
    servidor donde ESE bot esté invitado.

    Si la petición a Discord falla por CUALQUIER motivo (token de bot
    inválido, sin conexión, timeout, rate limit, respuesta no-JSON, etc.)
    devuelve una lista vacía en lugar de propagar la excepción, para que
    la vista nunca termine en un Error 500.
    """
    try:
        raw_channels = discord_get(f"/guilds/{guild_id}/channels", use_bot=True, bot_token=bot_token)
    except requests.RequestException:
        return []
    except (ValueError, KeyError):
        # Respuesta inesperada (no-JSON, estructura distinta, etc.)
        return []

    if types is not None:
        raw_channels = [c for c in raw_channels if c.get("type") in types]

    return sorted(raw_channels, key=lambda c: c.get("position", 0))


def fetch_guild_roles(guild_id, bot_token):
    """
    Devuelve los roles de un servidor (sin @everyone), usando el token del
    bot/cliente activo (bot_token).
    Igual que fetch_guild_channels: cualquier fallo devuelve [] en vez
    de tumbar la vista.
    """
    try:
        raw_roles = discord_get(f"/guilds/{guild_id}/roles", use_bot=True, bot_token=bot_token)
    except requests.RequestException:
        return []
    except (ValueError, KeyError):
        return []

    roles = [r for r in raw_roles if r.get("name") != "@everyone"]
    return sorted(roles, key=lambda r: -r.get("position", 0))


def roles_to_json(roles):
    """Versión ligera (id, name, color hex) para hidratar el selector de roles en JS."""
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "color": ("#%06x" % r["color"]) if r.get("color") else "#99aab5",
        }
        for r in roles
    ]


def safe_get_config():
    """
    get_config() protegido: si MongoDB no responde (credenciales, red, TLS...)
    o lanza cualquier otro error inesperado, devuelve la configuración por
    defecto en lugar de tumbar la vista con un 500.

    Se captura Exception en general (no solo PyMongoError) a propósito:
    documentos corruptos, timeouts que pymongo envuelve en tipos que no
    siempre heredan de PyMongoError, etc. no deben poder tumbar la página.
    """
    try:
        return get_config()
    except Exception as e:
        flash(
            "No se pudo leer la configuración desde MongoDB. Mostrando valores por defecto.",
            "error",
        )
        print(f"[WARN] safe_get_config(): {e}")
        return dict(DEFAULT_CONFIG)


def manageable_guilds(user_guilds):
    """Filtra los servidores donde el usuario puede administrar al bot."""
    result = []
    for g in user_guilds:
        perms = int(g.get("permissions", 0))
        if g.get("owner") or perms & PERM_MANAGE_GUILD or perms & PERM_ADMINISTRATOR:
            result.append(g)
    return result


def current_user():
    return session.get("discord_user")


def current_guild_id():
    return session.get("guild_id", "")


# ------------------------------------------------------------------
# Decoradores de acceso (SaaS multi-tenant)
# ------------------------------------------------------------------
def requires_login(view):
    """Exige que haya un usuario de Discord logueado con un bot_id activo en
    la sesión. Si está logueado pero sin bot asignado, lo manda a no_access."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Conéctate con Discord para continuar.", "error")
            return redirect(url_for("index"))
        if not current_bot_id():
            return redirect(url_for("no_access"))
        return view(*args, **kwargs)

    return wrapped


def requires_module(module_key):
    """Como requires_login, y además exige que el módulo `module_key` esté
    incluido en la licencia (allowed_modules) del bot/cliente activo. Si no
    lo está, bloquea la vista/POST y redirige al grid de módulos con un
    mensaje explicando que hay que contratarlo."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user():
                flash("Conéctate con Discord para continuar.", "error")
                return redirect(url_for("index"))
            if not current_bot_id():
                return redirect(url_for("no_access"))
            config = safe_get_config()
            if not modulo_permitido(config, module_key):
                flash(
                    f'El módulo "{module_key}" no está incluido en tu licencia actual. '
                    "Contacta con el administrador para contratarlo.",
                    "error",
                )
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def requires_admin(view):
    """Restringe una vista al propietario/administrador del SaaS (ADMIN_DISCORD_ID)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Conéctate con Discord para continuar.", "error")
            return redirect(url_for("index"))
        if not is_admin():
            flash("No tienes permisos para acceder al panel de administración.", "error")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


# ------------------------------------------------------------------
# Barra de "Modo Vista Previa" (simulación de clientes por el admin)
# ------------------------------------------------------------------
@app.context_processor
def inject_simulation_state():
    """
    Inyecta is_simulating / simulating_bot_name / is_admin_user en TODAS las
    plantillas automáticamente, sin tener que añadirlos a cada
    render_template(). Las plantillas solo necesitan
    {% include "_simulation_banner.html" %} para mostrar la barra de aviso
    cuando el admin está simulando a un cliente.

    IMPORTANTE: un context_processor se ejecuta en CADA render_template() de
    toda la app (incluidas las páginas de error/fallback). Si algo aquí
    dentro lanza una excepción sin capturar, tumbaría literalmente cualquier
    página con un 500 -- por eso todo el cuerpo va envuelto en try/except.
    """
    try:
        simulating = bool(session.get("is_simulating"))
        bot_name = ""
        if simulating and mongo_ready():
            bot_id = current_bot_id()
            doc = (
                config_collection.find_one({"_id": bot_id}, {"bot_name": 1})
                if bot_id
                else None
            )
            bot_name = (doc or {}).get("bot_name") or bot_id or ""
        elif simulating:
            bot_name = current_bot_id() or ""

        return {
            "is_simulating": simulating,
            "simulating_bot_name": bot_name,
            "is_admin_user": is_admin(),
        }
    except Exception as e:
        print(f"[WARN] inject_simulation_state(): {e}")
        return {"is_simulating": False, "simulating_bot_name": "", "is_admin_user": False}


# ------------------------------------------------------------------
# Autenticación con Discord (OAuth2)
# ------------------------------------------------------------------
@app.route("/login")
def login():
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
        "prompt": "consent",
    }
    return redirect(f"{DISCORD_API}/oauth2/authorize?{urlencode(params)}")


@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or state != session.get("oauth_state"):
        flash("No se pudo completar el inicio de sesión con Discord.", "error")
        return redirect(url_for("index"))

    # Intercambio del código OAuth2 por un access_token: cualquier fallo de
    # red/timeout con Discord, o una respuesta que no sea JSON válido, se
    # captura aquí -- nunca debe tumbar la vista con un 500.
    try:
        token_resp = requests.post(
            f"{DISCORD_API}/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        if not token_resp.ok:
            flash("Error autenticando con Discord.", "error")
            return redirect(url_for("index"))

        access_token = token_resp.json()["access_token"]
    except (requests.RequestException, ValueError, KeyError) as e:
        flash("No se pudo completar el inicio de sesión con Discord.", "error")
        print(f"[WARN] callback() intercambio de token: {e}")
        return redirect(url_for("index"))

    try:
        user = discord_get("/users/@me", token=access_token)
        guilds = discord_get("/users/@me/guilds", token=access_token)
    except (requests.RequestException, ValueError, KeyError) as e:
        flash("No se pudo obtener tu información de Discord.", "error")
        print(f"[WARN] callback() /users/@me: {e}")
        return redirect(url_for("index"))

    session["discord_token"] = access_token
    session["discord_user"] = user
    session["discord_guilds"] = manageable_guilds(guilds)

    # --- Resolución de bot_id activo (SaaS multi-tenant) ---
    discord_user_id = str(user.get("id", ""))
    if discord_user_id == ADMIN_DISCORD_ID:
        # El admin, al loguearse, siempre vuelve a ver su propio bot (deja de
        # simular a cualquier cliente que estuviera viendo antes).
        session["active_bot_id"] = ADMIN_PERSONAL_BOT_ID
        session.pop("is_simulating", None)
    elif mongo_ready():
        try:
            user_doc = users_collection.find_one({"_id": discord_user_id})
        except PyMongoError as e:
            user_doc = None
            flash("No se pudo comprobar tu acceso en MongoDB. Inténtalo de nuevo.", "error")
            print(f"[WARN] callback() users_collection.find_one: {e}")
        # Un cliente bloqueado por el admin (user_doc.blocked == True) NUNCA
        # obtiene un active_bot_id, aunque su documento todavía tenga
        # guardado un bot_id de antes de ser bloqueado -- current_bot_id()
        # aplica esta misma comprobación en cada request, así que esto es
        # solo para que la sesión arranque ya coherente desde el login.
        if user_doc and user_doc.get("blocked"):
            session["active_bot_id"] = None
        elif user_doc and user_doc.get("bot_id"):
            session["active_bot_id"] = user_doc["bot_id"]
        else:
            session["active_bot_id"] = None
    else:
        # Mongo no disponible: no podemos saber qué bot le corresponde, así
        # que lo mandamos a no_access en vez de crashear.
        session["active_bot_id"] = None
        flash("El sistema no está disponible en este momento. Inténtalo más tarde.", "error")

    # Si ya había un servidor guardado en Mongo de una sesión anterior, lo precargamos.
    if session.get("active_bot_id"):
        saved_guild_id = safe_get_config().get("guild_id")
        if saved_guild_id:
            session["guild_id"] = saved_guild_id

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/select-guild/<guild_id>")
def select_guild(guild_id):
    session["guild_id"] = guild_id
    try:
        save_fields({"guild_id": guild_id})
    except PyMongoError:
        pass
    return redirect(url_for("index"))


@app.route("/change-guild")
def change_guild():
    session.pop("guild_id", None)
    return redirect(url_for("index"))


# ------------------------------------------------------------------
# Vista principal
# ------------------------------------------------------------------
@app.route("/")
def index():
    """
    Vista principal (grid de módulos). Envuelta en try/except a propósito:
    si algo falla al leer/fusionar config (Mongo caído, un documento viejo
    con forma inesperada, etc.) NUNCA debe verse una página en blanco o un
    Error 500 silencioso -- se muestra el grid igualmente con los valores
    por defecto y un mensaje flash explicando qué pasó.
    """
    user = current_user()
    if user and not is_admin() and not current_bot_id():
        blocked = is_user_blocked(str(user.get("id", "")))
        return render_template("no_access.html", user=user, blocked=blocked)

    try:
        config = safe_get_config()
        return render_template(
            "modules.html",
            tickets_module=TICKETS_MODULE,
            moderation_module=MODERATION_MODULE,
            youtube_module=YOUTUBE_MODULE,
            twitch_module=TWITCH_MODULE,
            twitch_logs_module=TWITCH_LOGS_MODULE,
            wick_security_module=WICK_SECURITY_MODULE,
            config=config,
            user=current_user(),
            guilds=session.get("discord_guilds", []),
            guild_id=current_guild_id(),
        )
    except Exception as e:
        flash(f"No se pudo cargar el panel de módulos correctamente: {e}", "error")
        return render_template(
            "modules.html",
            tickets_module=TICKETS_MODULE,
            moderation_module=MODERATION_MODULE,
            youtube_module=YOUTUBE_MODULE,
            twitch_module=TWITCH_MODULE,
            twitch_logs_module=TWITCH_LOGS_MODULE,
            wick_security_module=WICK_SECURITY_MODULE,
            config=dict(DEFAULT_CONFIG),
            user=current_user(),
            guilds=session.get("discord_guilds", []),
            guild_id=current_guild_id(),
        )


@app.route("/no-access")
def no_access():
    """
    Página mostrada a un cliente logueado que todavía no tiene acceso a
    ningún panel de bot. Es el destino de url_for("no_access") usado por
    los decoradores requires_login/requires_module cuando current_bot_id()
    es None.

    IMPORTANTE: "sin bot asignado todavía" y "bloqueado por el admin" son
    dos situaciones muy distintas para el cliente -- el login con Discord
    se completó correctamente en ambos casos, así que el mensaje no debe
    sonar a que el inicio de sesión falló o a que hace falta "vincular un
    bot" para poder entrar. Se calcula aquí el motivo exacto para que la
    plantilla pueda mostrar el texto correcto en cada caso.
    """
    user = current_user()
    blocked = bool(user) and is_user_blocked(str(user.get("id", "")))
    return render_template("no_access.html", user=user, blocked=blocked)


@app.route("/api/modules/save", methods=["POST"])
@requires_login
def save_modules():
    """
    Guarda el estado on/off de los módulos completos (Tickets, Moderación) en
    un único bloque config['modules']. Se llama desde la barra flotante de
    cambios sin guardar de modules.html, junto con el resto de formularios
    marcados con data-autosave -- por eso NO guarda al instante al pulsar el
    switch, solo al confirmar "Guardar cambios".
    """
    # request.form.get(...) siempre encuentra estos campos porque el macro
    # module_card() de modules.html los renderiza como <input type="hidden">
    # con valor "true"/"false" (no como <input type="checkbox">), así que
    # capturamos correctamente tanto el estado ON como el OFF del switch.
    #
    # Nombres de input en inglés (modules_moderation / modules_tickets) para
    # que coincidan con las claves que lee el bot de Discord ("moderation" /
    # "tickets"). Se aceptan además los sufijos "_enabled" por compatibilidad
    # con integraciones o formularios alternativos que los usen.
    modules = {
        "moderation": (
            request.form.get("modules_moderation") == "true"
            or request.form.get("modules_moderation_enabled") == "true"
        ),
        "tickets": (
            request.form.get("modules_tickets") == "true"
            or request.form.get("modules_tickets_enabled") == "true"
        ),
        "youtube": (
            request.form.get("modules_youtube") == "true"
            or request.form.get("modules_youtube_enabled") == "true"
        ),
        "twitch": (
            request.form.get("modules_twitch") == "true"
            or request.form.get("modules_twitch_enabled") == "true"
        ),
        # Módulo independiente de "twitch" (ver TWITCH_LOGS_MODULE): su
        # propio switch, su propia licencia, su propia tarjeta.
        "twitch_logs": (
            request.form.get("modules_twitch_logs") == "true"
            or request.form.get("modules_twitch_logs_enabled") == "true"
        ),
        # Switch maestro del sistema Anti-Raid / WickSecurity (AutoMod/
        # AntiNuke/JoinGate/Cuarentena). Los 4 submódulos NO tienen tarjeta
        # propia en este grid -- se activan/desactivan individualmente paso
        # a paso dentro de /security-wick -- así que este switch solo
        # controla si TODO el sistema está licenciado/visible, no cada
        # submódulo por separado.
        "wick_security": (
            request.form.get("modules_wick_security") == "true"
            or request.form.get("modules_wick_security_enabled") == "true"
        ),
    }

    # Blindaje de licencia: aunque el POST pida activar un módulo, si no está
    # incluido en allowed_modules para este bot/cliente se fuerza a False.
    # Protege contra un request manipulado a mano que intente reactivar un
    # módulo bloqueado desde el Panel de Administración.
    config = safe_get_config()
    for key in modules:
        if not modulo_permitido(config, key):
            modules[key] = False

    # automod/antinuke/joingate/quarantine se controlan exclusivamente desde
    # sus propios pasos en /security-wick (save_wick_automod(), etc.), NO
    # desde este grid. save_fields({"modules": modules}) hace un $set que
    # REEMPLAZA todo el subdocumento "modules" -- si no preserváramos aquí
    # sus valores actuales, guardar cualquier cambio en la portada de
    # Módulos los resetearía silenciosamente a sus defaults.
    existing_modules = config.get("modules")
    existing_modules = existing_modules if isinstance(existing_modules, dict) else {}
    for sub_key in ("automod", "antinuke", "joingate", "quarantine"):
        modules[sub_key] = bool(existing_modules.get(sub_key, True))

    try:
        save_fields({"modules": modules})
        flash("Estado de los módulos actualizado correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("index"))


# ------------------------------------------------------------------
# Vista de configuración del módulo de Tickets
# ------------------------------------------------------------------
@app.route("/modulo/tickets")
@requires_module("tickets")
def tickets_config():
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    try:
        config = safe_get_config()
        bot_token = active_bot_token(config)
        channels = fetch_guild_channels(guild_id, bot_token, types=(0, 5))
        categories = fetch_guild_channels(guild_id, bot_token, types=(4,))
        roles = fetch_guild_roles(guild_id, bot_token)

        if not channels or not roles:
            flash(
                "No se pudieron cargar todos los canales/roles de ese servidor. "
                "Verifica que el bot esté invitado y tenga permisos.",
                "error",
            )

        return render_template(
            "tickets.html",
            config=config,
            message_types=MESSAGE_TYPES,
            variables=AVAILABLE_VARIABLES,
            channels=channels,
            categories=categories,
            roles=roles,
            roles_json=roles_to_json(roles),
            guild_id=guild_id,
            user=current_user(),
        )
    except Exception as e:
        flash(f"No se pudo cargar la configuración de Tickets: {e}", "error")
        return redirect(url_for("index"))


@app.route("/modulo/tickets/panel", methods=["POST"])
@requires_module("tickets")
def save_panel():
    tipo_mensaje = request.form.get("tipo_mensaje", "").strip()
    canal_id = request.form.get("canal_id", "").strip()
    categoria_id = request.form.get("categoria_id", "").strip()

    if tipo_mensaje not in MESSAGE_TYPES:
        flash("Tipo de mensaje inválido.", "error")
        return redirect(url_for("tickets_config") + "#panel")

    if not canal_id:
        flash("Selecciona el canal donde se enviará el panel.", "error")
        return redirect(url_for("tickets_config") + "#panel")

    fields = {"tipo_mensaje": tipo_mensaje, "canal_id": canal_id, "categoria_id": categoria_id}

    if tipo_mensaje == "text":
        mensaje = request.form.get("mensaje", "").strip()
        if not mensaje:
            flash("Escribe el mensaje del panel.", "error")
            return redirect(url_for("tickets_config") + "#panel")
        fields["mensaje"] = mensaje
    else:
        embed = {
            "author": request.form.get("embed_author", "").strip(),
            "title": request.form.get("embed_title", "").strip(),
            "description": request.form.get("embed_description", "").strip(),
            "footer": request.form.get("embed_footer", "").strip(),
            "image_url": request.form.get("embed_image_url", "").strip(),
            "thumbnail_url": request.form.get("embed_thumbnail_url", "").strip(),
            "color": request.form.get("embed_color", "#5865f2").strip() or "#5865f2",
        }
        if not embed["title"] and not embed["description"]:
            flash("El embed necesita al menos un título o una descripción.", "error")
            return redirect(url_for("tickets_config") + "#panel")
        fields["embed"] = embed

    try:
        save_fields(fields)
        flash("Panel de soporte guardado correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("tickets_config") + "#panel")


@app.route("/modulo/tickets/enviar-panel", methods=["POST"])
@requires_module("tickets")
def enviar_panel():
    """
    Envía (o reenvía) el panel de tickets ya guardado al canal configurado,
    usando el token del bot del cliente activo directamente contra la API
    REST de Discord (no depende de que el proceso del bot esté corriendo en
    ese momento).
    """
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    config = safe_get_config()
    bot_token = active_bot_token(config)
    canal_id = config.get("canal_id")
    if not canal_id:
        flash("Guarda primero un canal en 'Paneles de soporte' antes de enviar el panel.", "error")
        return redirect(url_for("tickets_config") + "#panel")

    # Botón "Abrir Ticket" (Discord Message Component: ActionRow > Button)
    payload = {
        "components": [
            {
                "type": 1,
                "components": [
                    {
                        "type": 2,
                        "style": 1,  # Primary (blurple)
                        "label": "Abrir Ticket",
                        "emoji": {"name": "🎫"},
                        "custom_id": "abrir_ticket",
                    }
                ],
            }
        ]
    }

    if config.get("tipo_mensaje") == "embed":
        embed_cfg = config.get("embed", {})
        embed = {}
        if embed_cfg.get("title"):
            embed["title"] = embed_cfg["title"]
        if embed_cfg.get("description"):
            embed["description"] = embed_cfg["description"]
        if embed_cfg.get("author"):
            embed["author"] = {"name": embed_cfg["author"]}
        if embed_cfg.get("footer"):
            embed["footer"] = {"text": embed_cfg["footer"]}
        if embed_cfg.get("image_url"):
            embed["image"] = {"url": embed_cfg["image_url"]}
        if embed_cfg.get("thumbnail_url"):
            embed["thumbnail"] = {"url": embed_cfg["thumbnail_url"]}

        color_hex = (embed_cfg.get("color") or "#5865f2").lstrip("#")
        try:
            embed["color"] = int(color_hex, 16)
        except ValueError:
            embed["color"] = 0x5865F2

        if not embed.get("title") and not embed.get("description"):
            flash("El embed guardado necesita al menos un título o una descripción.", "error")
            return redirect(url_for("tickets_config") + "#panel")

        payload["embeds"] = [embed]
    else:
        mensaje = (config.get("mensaje") or "").strip()
        if not mensaje:
            flash("Guarda primero el mensaje de texto del panel.", "error")
            return redirect(url_for("tickets_config") + "#panel")
        payload["content"] = mensaje

    try:
        resp = requests.post(
            f"{DISCORD_API}/channels/{canal_id}/messages",
            headers={
                "Authorization": f"Bot {bot_token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
    except requests.HTTPError:
        detalle = ""
        try:
            detalle = resp.json().get("message", "")
        except Exception:
            pass
        flash(f"No se pudo enviar el panel a Discord. {detalle}".strip(), "error")
        return redirect(url_for("tickets_config") + "#panel")

    flash("✅ Panel de tickets enviado al servidor correctamente.", "success")
    return redirect(url_for("tickets_config") + "#panel")


@app.route("/modulo/tickets/bienvenida", methods=["POST"])
@requires_module("tickets")
def save_bienvenida():
    tipo_mensaje = request.form.get("tipo_mensaje_bienvenida", "").strip()

    if tipo_mensaje not in MESSAGE_TYPES:
        flash("Tipo de mensaje inválido.", "error")
        return redirect(url_for("tickets_config") + "#bienvenida")

    # Se usa notación de punto para no pisar el resto del documento bot_config.
    fields = {"mensaje_bienvenida.tipo_mensaje": tipo_mensaje}

    if tipo_mensaje == "text":
        mensaje = request.form.get("bienvenida_mensaje", "").strip()
        if not mensaje:
            flash("Escribe el mensaje de apertura del ticket.", "error")
            return redirect(url_for("tickets_config") + "#bienvenida")
        fields["mensaje_bienvenida.mensaje"] = mensaje
    else:
        embed = {
            "author": request.form.get("bienvenida_embed_author", "").strip(),
            "title": request.form.get("bienvenida_embed_title", "").strip(),
            "description": request.form.get("bienvenida_embed_description", "").strip(),
            "footer": request.form.get("bienvenida_embed_footer", "").strip(),
            "image_url": request.form.get("bienvenida_embed_image_url", "").strip(),
            "thumbnail_url": request.form.get("bienvenida_embed_thumbnail_url", "").strip(),
            "color": request.form.get("bienvenida_embed_color", "#5865f2").strip() or "#5865f2",
        }
        if not embed["title"] and not embed["description"]:
            flash("El embed necesita al menos un título o una descripción.", "error")
            return redirect(url_for("tickets_config") + "#bienvenida")
        fields["mensaje_bienvenida.embed"] = embed

    try:
        save_fields(fields)
        flash("Mensaje de apertura de ticket guardado correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("tickets_config") + "#bienvenida")


@app.route("/api/guild-roles")
@requires_login
def api_guild_roles():
    """Devuelve en JSON los roles del servidor seleccionado (id, name, color)."""
    guild_id = current_guild_id()
    if not guild_id:
        return jsonify({"error": "No hay ningún servidor seleccionado."}), 400

    config = safe_get_config()
    bot_token = active_bot_token(config)
    roles = roles_to_json(fetch_guild_roles(guild_id, bot_token))
    roles.sort(key=lambda r: r["name"].lower())
    return jsonify(roles)


@app.route("/modulo/tickets/staff", methods=["POST"])
@requires_module("tickets")
def save_staff():
    # El selector de roles envía un campo oculto con las IDs separadas por comas
    # (name="staff_roles"), en lugar de un <select multiple>.
    raw = request.form.get("staff_roles", "")
    staff_roles = [role_id.strip() for role_id in raw.split(",") if role_id.strip()]

    try:
        save_fields({"staff_roles": staff_roles})
        flash("Roles de staff actualizados correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("tickets_config") + "#staff")


@app.route("/modulo/moderacion")
@requires_module("moderation")
def moderation_config():
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    # Bloque try/except general: cualquier fallo inesperado (Mongo, Discord,
    # plantilla, etc.) se captura aquí para no devolver un Error 500 al usuario.
    try:
        config = safe_get_config()
        bot_token = active_bot_token(config)
        channels = fetch_guild_channels(guild_id, bot_token, types=(0, 5))
        roles = fetch_guild_roles(guild_id, bot_token)

        if not channels or not roles:
            flash(
                "No se pudieron cargar todos los canales/roles de ese servidor. "
                "Verifica que el bot esté invitado y tenga permisos.",
                "error",
            )

        return render_template(
            "moderation.html",
            config=config,
            channels=channels,
            roles=roles,
            roles_json=roles_to_json(roles),
            guild_id=guild_id,
            moderation_commands=MODERATION_COMMANDS,
            user=current_user(),
        )
    except Exception as e:
        flash(f"No se pudo cargar la configuración de Moderación: {e}", "error")
        return redirect(url_for("index"))


@app.route("/modulo/moderacion/guardar", methods=["POST"])
@requires_module("moderation")
def save_moderation():
    mod_log_channel_id = request.form.get("mod_log_channel_id", "").strip()

    # Mismo formato que el selector de roles de Tickets: IDs separadas por comas
    # en un campo oculto (name="staff_roles").
    raw_roles = request.form.get("staff_roles", "")
    staff_roles = [role_id.strip() for role_id in raw_roles.split(",") if role_id.strip()]

    try:
        save_fields(
            {
                "mod_log_channel_id": mod_log_channel_id,
                "staff_roles": staff_roles,
            }
        )
        flash("Configuración de moderación guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("moderation_config"))


@app.route("/modulo/moderacion/comandos", methods=["POST"])
@requires_module("moderation")
def save_moderation_commands():
    """
    Guarda, para cada comando del módulo de Moderación, si está activo y qué
    roles pueden ejecutarlo. Estructura resultante en MongoDB:
      config['commands']['warn'] = {'enabled': True, 'roles': ['123', '456']}
    """
    commands = {}
    for cmd in MODERATION_COMMANDS:
        key = cmd["key"]
        enabled = f"cmd_{key}_enabled" in request.form
        raw_roles = request.form.get(f"cmd_{key}_roles", "")
        roles = [role_id.strip() for role_id in raw_roles.split(",") if role_id.strip()]
        commands[key] = {"enabled": enabled, "roles": roles}

    try:
        save_fields({"commands": commands})
        flash("Permisos por comando guardados correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("moderation_config") + "#comandos")


@app.route("/modulo/tickets/features", methods=["POST"])
@requires_module("tickets")
def save_features():
    transcript_enabled = "transcript" in request.form
    transcript_channel_id = request.form.get("transcript_channel_id", "").strip()

    if transcript_enabled and not transcript_channel_id:
        flash("Selecciona el canal donde se enviarán los transcripts.", "error")
        return redirect(url_for("tickets_config") + "#features")

    features = {
        "close": "close" in request.form,
        "claim": "claim" in request.form,
        "transcript": transcript_enabled,
        "transcript_channel_id": transcript_channel_id if transcript_enabled else "",
        "add_remove_users": "add_remove_users" in request.form,
    }

    try:
        save_fields({"features": features})
        flash("Funciones opcionales actualizadas correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("tickets_config") + "#features")


# ------------------------------------------------------------------
# Vista de configuración del módulo de YouTube (vídeos y directos)
# ------------------------------------------------------------------
@app.route("/youtube")
@requires_module("youtube")
def youtube_config():
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    try:
        config = safe_get_config()
        bot_token = active_bot_token(config)
        channels = fetch_guild_channels(guild_id, bot_token, types=(0, 5))
        roles = fetch_guild_roles(guild_id, bot_token)

        if not channels or not roles:
            flash(
                "No se pudieron cargar todos los canales/roles de ese servidor. "
                "Verifica que el bot esté invitado y tenga permisos.",
                "error",
            )

        return render_template(
            "youtube.html",
            config=config,
            variables=YOUTUBE_VARIABLES,
            channels=channels,
            roles=roles,
            guild_id=guild_id,
            user=current_user(),
        )
    except Exception as e:
        flash(f"No se pudo cargar la configuración de YouTube: {e}", "error")
        return redirect(url_for("index"))


@app.route("/youtube/save", methods=["POST"])
@requires_module("youtube")
def save_youtube():
    """
    Guarda las secciones de Vídeos y Directos de forma independiente, usando
    notación de punto (youtube.videos / youtube.streams) para NO tocar
    youtube.notified_ids -- ese campo es estado gestionado por el bot (IDs ya
    notificados) y debe sobrevivir a cualquier guardado desde el dashboard.

    "channel_id" se guarda TAL CUAL lo escribe el usuario (URL completa,
    @handle o ID de YouTube) -- solo se le quita espacios en blanco. No se
    parsea ni se valida el formato aquí: es el bot (cogs/youtube.py) quien
    debe normalizar el valor y extraer el ID/handle real antes de consultar
    la API de YouTube.
    """
    form = request.form

    videos = {
        "enabled": "videos_enabled" in form,
        "channel_id": form.get("videos_channel_id", "").strip(),
        "discord_channel_id": form.get("videos_discord_channel_id", "").strip(),
        "ping_role_id": form.get("videos_ping_role_id", "").strip(),
        "mensaje": form.get("videos_mensaje", "").strip(),
        "notify_videos": "videos_notify_videos" in form,
        "notify_shorts": "videos_notify_shorts" in form,
    }

    streams = {
        "enabled": "streams_enabled" in form,
        "channel_id": form.get("streams_channel_id", "").strip(),
        "discord_channel_id": form.get("streams_discord_channel_id", "").strip(),
        "ping_role_id": form.get("streams_ping_role_id", "").strip(),
        "mensaje": form.get("streams_mensaje", "").strip(),
    }

    try:
        save_fields({"youtube.videos": videos, "youtube.streams": streams})
        flash("Configuración de YouTube guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("youtube_config"))


# ------------------------------------------------------------------
# Logs de sanciones de Twitch en tiempo real (EventSub)
# ------------------------------------------------------------------
def get_twitch_app_access_token(client_id, client_secret):
    """
    App Access Token (client credentials grant) de la app de Twitch de UN
    cliente concreto. Es el token con el que se crean las suscripciones
    EventSub -- Twitch exige un App Access Token para el transporte
    "webhook", nunca el token de usuario del streamer (ese solo demuestra
    que el streamer autorizó los scopes necesarios).
    """
    resp = requests.post(
        f"{TWITCH_AUTH_API}/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_twitch_channel_choices(client_id, access_token):
    """
    Devuelve la lista de canales candidatos a monitorizar: el propio canal
    del streamer autenticado (siempre primero) + los canales donde su
    cuenta es moderadora (GET /helix/moderation/channels, requiere el scope
    "user:read:moderated_channels"). Cada elemento es
    {"id", "login", "display_name"}.

    Si la llamada a moderation/channels falla (por ejemplo, una cuenta
    vinculada antes de añadir ese scope) no se rompe la vinculación entera:
    simplemente se devuelve solo el canal propio.
    """
    headers = {"Client-Id": client_id, "Authorization": f"Bearer {access_token}"}

    users_resp = requests.get(f"{TWITCH_HELIX_API}/users", headers=headers, timeout=10)
    users_resp.raise_for_status()
    users_data = users_resp.json().get("data") or []
    if not users_data:
        raise ValueError("Twitch no devolvió información del usuario autenticado.")

    own = users_data[0]
    choices = [{
        "id": own["id"],
        "login": own.get("login", ""),
        "display_name": own.get("display_name") or own.get("login", ""),
    }]
    seen_ids = {own["id"]}

    try:
        mod_resp = requests.get(
            f"{TWITCH_HELIX_API}/moderation/channels",
            headers=headers,
            params={"user_id": own["id"], "first": 100},
            timeout=10,
        )
        mod_resp.raise_for_status()
        for ch in mod_resp.json().get("data") or []:
            ch_id = ch.get("broadcaster_id")
            if not ch_id or ch_id in seen_ids:
                continue
            seen_ids.add(ch_id)
            choices.append({
                "id": ch_id,
                "login": ch.get("broadcaster_login", ""),
                "display_name": ch.get("broadcaster_name") or ch.get("broadcaster_login", ""),
            })
    except requests.RequestException as e:
        print(f"[WARN] No se pudieron obtener los canales moderados de Twitch: {e}")

    return choices


def _twitch_eventsub_condition(sub_type, broadcaster_id, moderator_id):
    """
    Condition exigido por cada tipo de suscripción (ver
    https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/).

    IMPORTANTE: broadcaster_id es el canal que se está monitorizando (puede
    ser el propio o uno que el cliente modera), mientras que moderator_id es
    SIEMPRE la cuenta de Twitch que hizo login por OAuth y concedió los
    scopes a nuestra app (twitch.linked_user_id). Cuando ambos coinciden
    (monitorizas tu propio canal) da igual, pero si eliges un canal ajeno
    que moderas, Twitch exige que moderator_user_id/user_id sea la cuenta
    que realmente autorizó -- si se pone ahí el ID del broadcaster (que
    nunca autorizó nada a esta app), Twitch responde "subscription missing
    proper authorization".

    "channel.ban" es un caso aparte: su condition oficial SOLO admite
    broadcaster_user_id (no hay campo para indicar "qué moderador
    autoriza"), así que Twitch únicamente puede validarlo contra un scope
    channel:moderate concedido por el PROPIO broadcaster del canal. Si el
    canal elegido no es el tuyo, esta suscripción en concreto seguirá
    fallando con "missing proper authorization" aunque seas moderador --
    es una limitación de la API de Twitch, no de este código. Para que
    funcione, el streamer dueño de ese canal tendría que vincular también
    su cuenta (aunque sea solo para autorizar, sin necesidad de usarla
    activamente para nada más).
    """
    if sub_type == "channel.ban":
        return {"broadcaster_user_id": broadcaster_id}
    if sub_type == "channel.warning.send":
        return {"broadcaster_user_id": broadcaster_id, "moderator_user_id": moderator_id}
    if sub_type == "channel.chat.message_delete":
        return {"broadcaster_user_id": broadcaster_id, "user_id": moderator_id}
    raise ValueError(f"Tipo de suscripción EventSub no soportado: {sub_type}")


def create_twitch_eventsub_subscription(app_access_token, client_id, sub_type, version, condition):
    """
    Crea UNA suscripción EventSub (transporte webhook) en la API de Twitch.
    Devuelve el subscription_id si se creó, o None si Twitch responde 409
    Conflict porque ya existe una suscripción idéntica (mismo
    type+condition+callback) -- se trata como éxito, no como error, para
    que volver a vincular la cuenta sea una operación idempotente y segura.
    Cualquier otro fallo (scope no concedido, credenciales inválidas, etc.)
    se propaga como requests.HTTPError para que la llamada lo capture.
    """
    resp = requests.post(
        f"{TWITCH_HELIX_API}/eventsub/subscriptions",
        headers={
            "Client-Id": client_id,
            "Authorization": f"Bearer {app_access_token}",
            "Content-Type": "application/json",
        },
        json={
            "type": sub_type,
            "version": version,
            "condition": condition,
            "transport": {
                "method": "webhook",
                "callback": TWITCH_EVENTSUB_CALLBACK_URL,
                "secret": TWITCH_EVENTSUB_SECRET,
            },
        },
        timeout=10,
    )
    if resp.status_code == 409:
        return None
    resp.raise_for_status()
    data = resp.json().get("data") or []
    return data[0]["id"] if data else None


def ensure_twitch_eventsub_subscriptions(config, broadcaster_id):
    """
    Crea (o reutiliza) las 3 suscripciones EventSub de sanciones para
    broadcaster_id, usando el Client ID/Secret de Twitch de ESTE cliente
    (config['twitch']['credentials']). Guarda los subscription_id
    resultantes en twitch.subscription_ids del bot/cliente activo de la
    sesión.

    Devuelve (subscription_ids, errores): un fallo en un tipo de
    suscripción (p.ej. un scope que Twitch todavía no concedió) NUNCA
    bloquea a los demás -- cada uno se intenta por separado y los errores
    se acumulan para poder avisar al cliente sin perder las suscripciones
    que sí se crearon correctamente.

    Lanza ValueError si falta algún requisito previo (secreto del webhook
    sin configurar en el servidor, o Client ID/Secret de Twitch del cliente
    todavía vacíos) -- son errores de configuración, no de Twitch, así que
    se distinguen para poder mostrar un mensaje claro.
    """
    if not TWITCH_EVENTSUB_SECRET:
        raise ValueError(
            "Falta configurar la variable de entorno TWITCH_EVENTSUB_SECRET en el servidor."
        )

    credentials = config.get("twitch", {}).get("credentials", {})
    client_id = credentials.get("client_id", "")
    client_secret = credentials.get("client_secret", "")
    if not client_id or not client_secret:
        raise ValueError(
            "Configura primero el Client ID y Client Secret de tu app de Twitch en esta página."
        )

    # Cuenta que realmente autorizó los scopes (ver _twitch_eventsub_condition).
    # Si por lo que sea no está guardada (vinculaciones antiguas, previas a
    # este campo), usamos broadcaster_id como fallback -- es el comportamiento
    # de antes, correcto solo cuando se monitoriza el propio canal.
    moderator_id = config.get("twitch", {}).get("linked_user_id") or broadcaster_id

    app_token = get_twitch_app_access_token(client_id, client_secret)

    subscription_ids = {}
    errors = []
    for sub in TWITCH_EVENTSUB_SUBSCRIPTIONS:
        try:
            condition = _twitch_eventsub_condition(sub["type"], broadcaster_id, moderator_id)
            sub_id = create_twitch_eventsub_subscription(
                app_token, client_id, sub["type"], sub["version"], condition
            )
            if sub_id:
                subscription_ids[sub["type"]] = sub_id
        except requests.HTTPError as e:
            detail = ""
            try:
                detail = e.response.json().get("message", "")
            except Exception:
                pass
            errors.append(f"{sub['type']}: {detail or e}")

    if subscription_ids:
        try:
            save_fields({"twitch.subscription_ids": subscription_ids})
        except PyMongoError:
            pass

    return subscription_ids, errors


def send_discord_log_embed(bot_token, channel_id, embed):
    """
    Envía UN embed al canal de Discord de un cliente usando su propio
    bot_token, vía la API REST de Discord directamente (igual patrón que
    save_panel() para tickets) -- no depende de que el proceso del bot
    (discord.py) esté corriendo ni de discord.py en absoluto, así que
    funciona igual de bien llamado desde una vista con sesión que desde el
    webhook de EventSub, que no tiene sesión Flask.
    """
    resp = requests.post(
        f"{DISCORD_API}/channels/{channel_id}/messages",
        headers={
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json",
        },
        json={"embeds": [embed]},
        timeout=10,
    )
    resp.raise_for_status()


# Colores de cada tipo de sanción (enteros RGB, formato que espera la API de
# Discord para "color" dentro de un embed).
# ------------------------------------------------------------------
# Plantillas de embed de los logs de sanciones de Twitch -- EXCLUSIVAS del
# administrador del SaaS (ADMIN_DISCORD_ID). Se guardan en un único
# documento GLOBAL (settings_collection, _id=TWITCH_EMBED_TEMPLATES_ID), NO
# por bot_id: es el mismo aspecto visual para todos los clientes, y ningún
# cliente puede editarlo desde su propio dashboard (solo /admin/*, detrás de
# @requires_admin). Los clientes solo eligen canal y filtros (on/off); el
# admin controla título, descripción, color y footer de cada tipo de aviso.
# ------------------------------------------------------------------
TWITCH_EMBED_TEMPLATES_ID = "twitch_embed_templates"

TWITCH_EMBED_LABELS = {
    "ban": "🔨 Baneo permanente",
    "timeout": "⏱️ Timeout",
    "warning": "⚠️ Advertencia",
    "delete_message": "🗑️ Mensaje borrado",
}

DEFAULT_TWITCH_EMBED_TEMPLATES = {
    "ban": {
        "title": "🔨 Baneo permanente en Twitch",
        "description": "**{usuario}** ha sido baneado permanentemente por **{moderador}**.\n\n**Motivo:** {motivo}",
        "color": "ED4245",
        "footer": "Twitch · {canal}",
    },
    "timeout": {
        "title": "⏱️ Timeout en Twitch",
        "description": "**{usuario}** ha sido silenciado temporalmente por **{moderador}**.\n\n**Motivo:** {motivo}\n**Finaliza:** {finaliza}",
        "color": "F5A623",
        "footer": "Twitch · {canal}",
    },
    "warning": {
        "title": "⚠️ Advertencia en Twitch",
        "description": "**{usuario}** ha recibido una advertencia de **{moderador}**.\n\n**Motivo:** {motivo}\n**Reglas citadas:** {reglas}",
        "color": "FAA61A",
        "footer": "Twitch · {canal}",
    },
    "delete_message": {
        "title": "🗑️ Mensaje borrado en Twitch",
        "description": "Se ha borrado un mensaje de **{usuario}** en el chat.\n\n**ID del mensaje:** `{mensaje_id}`\n\n*Twitch no incluye el moderador ni el contenido del mensaje borrado en este evento.*",
        "color": "5865F2",
        "footer": "Twitch · {canal}",
    },
}

# Variables insertables por tipo, para el panel de "variables disponibles"
# del editor de embeds del admin (mismo patrón que vars_panel en twitch.html
# / tickets.html).
TWITCH_EMBED_VARIABLES = {
    "ban": [
        {"token": "{usuario}", "label": "Usuario baneado"},
        {"token": "{moderador}", "label": "Moderador"},
        {"token": "{motivo}", "label": "Motivo"},
        {"token": "{fecha}", "label": "Fecha del baneo"},
        {"token": "{canal}", "label": "Canal de Twitch"},
    ],
    "timeout": [
        {"token": "{usuario}", "label": "Usuario"},
        {"token": "{moderador}", "label": "Moderador"},
        {"token": "{motivo}", "label": "Motivo"},
        {"token": "{finaliza}", "label": "Fecha en que termina"},
        {"token": "{fecha}", "label": "Fecha del timeout"},
        {"token": "{canal}", "label": "Canal de Twitch"},
    ],
    "warning": [
        {"token": "{usuario}", "label": "Usuario"},
        {"token": "{moderador}", "label": "Moderador"},
        {"token": "{motivo}", "label": "Motivo"},
        {"token": "{reglas}", "label": "Reglas de chat citadas"},
        {"token": "{fecha}", "label": "Fecha"},
        {"token": "{canal}", "label": "Canal de Twitch"},
    ],
    "delete_message": [
        {"token": "{usuario}", "label": "Usuario del mensaje borrado"},
        {"token": "{mensaje_id}", "label": "ID del mensaje"},
        {"token": "{fecha}", "label": "Fecha"},
        {"token": "{canal}", "label": "Canal de Twitch"},
    ],
}


def get_twitch_embed_templates():
    """
    Plantillas actuales (guardadas por el admin, con fallback a los
    defaults campo a campo si todavía no se han guardado o falta alguno).
    Nunca lanza si Mongo no está disponible -- devuelve los defaults.
    """
    templates = {key: dict(value) for key, value in DEFAULT_TWITCH_EMBED_TEMPLATES.items()}
    if settings_collection is None:
        return templates
    try:
        doc = settings_collection.find_one({"_id": TWITCH_EMBED_TEMPLATES_ID}) or {}
    except PyMongoError:
        return templates
    for key in templates:
        stored = doc.get(key)
        if isinstance(stored, dict):
            templates[key].update({k: v for k, v in stored.items() if k in ("title", "description", "color", "footer")})
    return templates


def _render_twitch_embed_template(template, variables):
    """Sustituye cada {token} de `variables` en title/description/footer de
    la plantilla, y convierte el color hex guardado (ej. "ED4245") a el
    entero que espera la API de Discord."""

    def _fill(text):
        text = text or ""
        for token, value in variables.items():
            text = text.replace(token, str(value) if value else "")
        return text.strip()

    color_hex = (template.get("color") or "5865F2").strip().lstrip("#") or "5865F2"
    try:
        color = int(color_hex, 16)
    except ValueError:
        color = 0x5865F2

    embed = {"color": color}
    title = _fill(template.get("title"))
    description = _fill(template.get("description"))
    footer_text = _fill(template.get("footer"))
    if title:
        embed["title"] = title
    if description:
        embed["description"] = description
    if footer_text:
        embed["footer"] = {"text": footer_text}
    return embed


def _twitch_moderation_embed(sub_type, event, broadcaster_display_name=""):
    """
    Construye el embed de Discord a partir del tipo de suscripción EventSub,
    su payload completo, y la plantilla que haya definido el ADMIN para ese
    tipo de sanción (get_twitch_embed_templates()) -- el cliente nunca
    controla el aspecto del embed, solo el canal de destino y qué tipos
    quiere recibir. Devuelve (filter_key, embed); (None, None) si el tipo de
    evento no se reconoce.

    Variables disponibles por tipo (documentación oficial de Twitch,
    eventsub-subscription-types):
      - channel.ban: user_id/login/name, moderator_user_id/login/name,
        reason, banned_at, ends_at, is_permanent.
      - channel.warning.send: user_id/login/name, moderator_user_id/login/
        name, reason, chat_rules_cited (lista).
      - channel.chat.message_delete: SOLO target_user_id/login/name y
        message_id -- Twitch no manda ni moderador ni motivo ni el
        contenido del mensaje borrado (limitación de privacidad de su API,
        no un recorte nuestro).
    """
    user = event.get("user_name") or event.get("user_login") or "Desconocido"
    moderator = event.get("moderator_user_name") or event.get("moderator_user_login") or "Desconocido"
    canal = (
        broadcaster_display_name
        or event.get("broadcaster_user_name")
        or event.get("broadcaster_user_login")
        or "Desconocido"
    )

    if sub_type == "channel.ban":
        is_permanent = bool(event.get("is_permanent"))
        filter_key = "ban" if is_permanent else "timeout"
        variables = {
            "{usuario}": user,
            "{moderador}": moderator,
            "{motivo}": event.get("reason") or "Sin motivo especificado",
            "{finaliza}": event.get("ends_at") or "No aplica",
            "{fecha}": event.get("banned_at") or "",
            "{canal}": canal,
        }
    elif sub_type == "channel.warning.send":
        filter_key = "warning"
        rules = event.get("chat_rules_cited") or []
        variables = {
            "{usuario}": user,
            "{moderador}": moderator,
            "{motivo}": event.get("reason") or "Sin motivo especificado",
            "{reglas}": ", ".join(rules) if rules else "Ninguna especificada",
            "{fecha}": "",
            "{canal}": canal,
        }
    elif sub_type == "channel.chat.message_delete":
        filter_key = "delete_message"
        target = event.get("target_user_name") or event.get("target_user_login") or "Desconocido"
        variables = {
            "{usuario}": target,
            "{mensaje_id}": event.get("message_id", "desconocido"),
            "{fecha}": "",
            "{canal}": canal,
        }
    else:
        return None, None

    templates = get_twitch_embed_templates()
    template = templates.get(filter_key, DEFAULT_TWITCH_EMBED_TEMPLATES[filter_key])
    embed = _render_twitch_embed_template(template, variables)
    return filter_key, embed


def handle_twitch_eventsub_notification(sub_type, event):
    """
    Procesa UNA notificación de sanción ya verificada (firma HMAC correcta).
    Busca el bot/cliente dueño de ese broadcaster_id, respeta sus filtros
    (twitch.filters) y, si corresponde, envía el aviso (como embed) a su
    canal de Discord (twitch.log_channel_id) con su propio bot_token --
    todo completamente aislado por cliente, nunca se mezclan datos de un
    cliente con los de otro.
    """
    broadcaster_id = event.get("broadcaster_user_id")
    if not broadcaster_id or not mongo_ready():
        return

    doc = config_collection.find_one({"twitch.broadcaster_id": broadcaster_id})
    if not doc:
        # Ningún cliente tiene este broadcaster_id vinculado (o se
        # desvinculó). Es un ack normal, no un error: Twitch no debe
        # reintentar esta notificación.
        print(f"[WARN] EventSub: broadcaster_id {broadcaster_id} sin cliente asociado.")
        return

    bot_id = doc["_id"]
    config = get_config(bot_id=bot_id)
    twitch_cfg = config.get("twitch", {})

    filter_key, embed = _twitch_moderation_embed(
        sub_type, event, twitch_cfg.get("broadcaster_display_name", "")
    )
    if not filter_key or not embed:
        return

    if not twitch_cfg.get("filters", {}).get(filter_key, True):
        return  # El cliente desactivó este tipo de aviso.

    log_channel_id = twitch_cfg.get("log_channel_id")
    if not log_channel_id:
        return  # No ha elegido todavía un canal de Discord para los logs.

    # El título/descripción/color/footer ya vienen resueltos desde la
    # plantilla del admin (_twitch_moderation_embed); aquí solo se añade la
    # marca de tiempo real del evento.
    embed["timestamp"] = datetime.now(timezone.utc).isoformat()

    bot_token = active_bot_token(config)
    try:
        send_discord_log_embed(bot_token, log_channel_id, embed)
    except requests.RequestException as e:
        print(f"[WARN] No se pudo enviar el aviso de sanción de Twitch a Discord (bot_id={bot_id}): {e}")


@app.route("/twitch/oauth/login")
@requires_module("twitch_logs")
def twitch_oauth_login():
    """
    Paso 1 de la vinculación de la cuenta de Twitch del cliente: lo manda a
    autorizar en Twitch los scopes necesarios para las 3 suscripciones
    EventSub de sanciones, incluido el scope para listar los canales que
    modera. Es una acción del módulo "Logs Twitch" (twitch_logs) -- el
    Client ID/Secret que usa se configura en esta misma página. Requiere
    que el cliente ya lo haya guardado -- exactamente igual que Discord: el
    login autentica, nunca crea ni vincula nada por sí solo hasta que el
    cliente confirma en la pantalla de autorización de Twitch.
    """
    config = safe_get_config()
    client_id = config.get("twitch", {}).get("credentials", {}).get("client_id", "")
    if not client_id:
        flash(
            "Configura primero el Client ID de tu app de Twitch antes de vincular la cuenta.",
            "error",
        )
        return redirect(url_for("twitch_logs_config"))

    state = secrets.token_urlsafe(16)
    session["twitch_oauth_state"] = state
    params = {
        "client_id": client_id,
        "redirect_uri": TWITCH_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(TWITCH_OAUTH_SCOPES),
        "state": state,
        "force_verify": "true",
    }
    return redirect(f"{TWITCH_AUTH_API}/authorize?{urlencode(params)}")


@app.route("/twitch/oauth/callback")
@requires_module("twitch_logs")
def twitch_oauth_callback():
    """
    Paso 2: Twitch redirige aquí con un "code" tras la autorización del
    streamer. Intercambia el code por access_token/refresh_token, obtiene
    el canal propio y los canales que modera (GET /helix/users +
    /helix/moderation/channels), cifra y guarda todo, y finalmente crea las
    3 suscripciones EventSub para el canal seleccionado (el propio por
    defecto -- el cliente puede cambiarlo luego con el desplegable de
    "Logs Twitch" sin tener que volver a vincular la cuenta).
    """
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error_description") or request.args.get("error")

    if error:
        flash(f"Twitch denegó la autorización: {error}", "error")
        return redirect(url_for("twitch_logs_config"))

    if not code or state != session.get("twitch_oauth_state"):
        flash("No se pudo completar la vinculación con Twitch.", "error")
        return redirect(url_for("twitch_logs_config"))
    session.pop("twitch_oauth_state", None)

    config = safe_get_config()
    credentials = config.get("twitch", {}).get("credentials", {})
    client_id = credentials.get("client_id", "")
    client_secret = credentials.get("client_secret", "")
    if not client_id or not client_secret:
        flash(
            "Configura primero el Client ID y Client Secret de tu app de Twitch.",
            "error",
        )
        return redirect(url_for("twitch_logs_config"))

    try:
        token_resp = requests.post(
            f"{TWITCH_AUTH_API}/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": TWITCH_OAUTH_REDIRECT_URI,
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token", "")
    except (requests.RequestException, ValueError, KeyError) as e:
        flash(f"No se pudo intercambiar el código de Twitch por un token: {e}", "error")
        return redirect(url_for("twitch_logs_config"))

    try:
        choices = fetch_twitch_channel_choices(client_id, access_token)
    except (requests.RequestException, ValueError, KeyError, IndexError) as e:
        flash(f"No se pudo obtener tu(s) canal(es) de Twitch: {e}", "error")
        return redirect(url_for("twitch_logs_config"))

    if not choices:
        flash("Twitch no devolvió ningún canal válido.", "error")
        return redirect(url_for("twitch_logs_config"))

    # Si ya había un canal elegido antes y sigue siendo una opción válida, se
    # mantiene (revincular/renovar permisos no debe cambiar el canal
    # monitorizado). Si no, se usa el canal propio (siempre el primero de la
    # lista) como opción por defecto.
    previous_broadcaster_id = config.get("twitch", {}).get("broadcaster_id", "")
    selected = next((c for c in choices if c["id"] == previous_broadcaster_id), choices[0])
    # choices[0] es SIEMPRE el canal propio (ver fetch_twitch_channel_choices),
    # es decir, la cuenta que acaba de autorizar los scopes vía OAuth.
    own_account = choices[0]

    try:
        save_fields(
            {
                "twitch.access_token": encrypt_secret(access_token),
                "twitch.refresh_token": encrypt_secret(refresh_token),
                "twitch.available_channels": choices,
                "twitch.broadcaster_id": selected["id"],
                "twitch.broadcaster_login": selected["login"],
                "twitch.broadcaster_display_name": selected["display_name"],
                "twitch.linked_user_id": own_account["id"],
                "twitch.linked_login": own_account["login"],
            }
        )
    except PyMongoError as e:
        flash(f"No se pudo guardar la vinculación con Twitch: {e}", "error")
        return redirect(url_for("twitch_logs_config"))

    config = safe_get_config()  # recarga ya con broadcaster_id/credenciales frescas
    try:
        _, errors = ensure_twitch_eventsub_subscriptions(config, selected["id"])
    except ValueError as e:
        flash(f"Cuenta de Twitch vinculada, pero no se pudieron activar los avisos: {e}", "error")
        return redirect(url_for("twitch_logs_config"))

    if errors:
        msg = (
            "Cuenta de Twitch vinculada. Algunos avisos no se pudieron activar: "
            + "; ".join(errors)
        )
        if selected["id"] != own_account["id"] and any(e.startswith("channel.ban") for e in errors):
            msg += (
                " — el aviso de baneos/timeouts (channel.ban) solo puede activarse si el "
                f"propio dueño del canal ({selected['display_name']}) vincula también su "
                "cuenta de Twitch; ser moderador no es suficiente para ese tipo de aviso "
                "en concreto (limitación de Twitch, no del panel). El resto de avisos "
                "(advertencias y mensajes borrados) sí funcionan solo con tu cuenta."
            )
        flash(msg, "error")
    else:
        flash(
            f"✅ Cuenta de Twitch vinculada. Monitorizando el canal de "
            f"{selected['display_name']}. Puedes cambiarlo abajo si quieres.",
            "success",
        )

    return redirect(url_for("twitch_logs_config"))


@app.route("/twitch/logs/select-channel", methods=["POST"])
@requires_module("twitch_logs")
def select_twitch_channel():
    """
    Cambia qué canal de Twitch (propio o uno de los que modera el usuario)
    se monitoriza, sin tener que volver a pasar por el OAuth completo. Solo
    acepta un broadcaster_id que ya esté en twitch.available_channels (la
    lista construida en el último login/relink) -- nunca un ID arbitrario
    del formulario, para no poder suscribirse a canales ajenos.
    """
    config = safe_get_config()
    twitch_cfg = config.get("twitch", {})
    choices = twitch_cfg.get("available_channels", [])

    chosen_id = request.form.get("broadcaster_id", "").strip()
    selected = next((c for c in choices if c["id"] == chosen_id), None)
    if not selected:
        flash("Selecciona un canal válido de la lista.", "error")
        return redirect(url_for("twitch_logs_config"))

    try:
        save_fields(
            {
                "twitch.broadcaster_id": selected["id"],
                "twitch.broadcaster_login": selected["login"],
                "twitch.broadcaster_display_name": selected["display_name"],
            }
        )
    except PyMongoError as e:
        flash(f"No se pudo guardar el canal seleccionado: {e}", "error")
        return redirect(url_for("twitch_logs_config"))

    config = safe_get_config()
    try:
        _, errors = ensure_twitch_eventsub_subscriptions(config, selected["id"])
    except ValueError as e:
        flash(f"Canal actualizado, pero no se pudieron activar los avisos: {e}", "error")
        return redirect(url_for("twitch_logs_config"))

    is_own_channel = selected["id"] == config.get("twitch", {}).get("linked_user_id")
    if errors:
        msg = (
            f"Canal actualizado a {selected['display_name']}. Algunos avisos no se pudieron activar: "
            + "; ".join(errors)
        )
        if not is_own_channel and any(e.startswith("channel.ban") for e in errors):
            msg += (
                " — el aviso de baneos/timeouts (channel.ban) solo puede activarse si el "
                f"propio dueño del canal ({selected['display_name']}) vincula también su "
                "cuenta de Twitch; ser moderador no es suficiente para ese tipo de aviso "
                "en concreto (limitación de Twitch, no del panel). El resto de avisos "
                "(advertencias y mensajes borrados) sí funcionan solo con tu cuenta."
            )
        flash(msg, "error")
    else:
        flash(f"✅ Ahora se monitoriza el canal de {selected['display_name']}.", "success")

    return redirect(url_for("twitch_logs_config"))


@app.route("/webhooks/twitch/eventsub", methods=["POST"])
def twitch_eventsub_webhook():
    """
    Endpoint público (sin sesión, sin @requires_login) que recibe TODAS las
    notificaciones de EventSub de TODOS los clientes -- Twitch llama a esta
    misma URL fija para cualquier broadcaster suscrito; el aislamiento por
    cliente se hace dentro de handle_twitch_eventsub_notification() buscando
    el bot_id dueño de cada broadcaster_id.

    Verificación obligatoria antes de confiar en nada del payload: la firma
    HMAC-SHA256 en Twitch-Eventsub-Message-Signature, calculada por Twitch
    sobre (message_id + timestamp + cuerpo crudo) con TWITCH_EVENTSUB_SECRET.
    Sin esto, cualquiera podría enviar avisos falsos de sanciones a los
    canales de Discord de los clientes.
    """
    if not TWITCH_EVENTSUB_SECRET:
        # Nunca debería llegar tráfico real aquí si no se configuró el
        # secreto, pero por si acaso: rechazar en vez de procesar sin
        # verificar nada.
        return ("EventSub no configurado", 500)

    message_id = request.headers.get("Twitch-Eventsub-Message-Id", "")
    timestamp = request.headers.get("Twitch-Eventsub-Message-Timestamp", "")
    signature = request.headers.get("Twitch-Eventsub-Message-Signature", "")
    message_type = request.headers.get("Twitch-Eventsub-Message-Type", "")
    raw_body = request.get_data()  # bytes crudos -- la firma se calcula sobre esto, NUNCA sobre request.json

    expected = (
        "sha256="
        + hmac.new(
            TWITCH_EVENTSUB_SECRET.encode(),
            message_id.encode() + timestamp.encode() + raw_body,
            hashlib.sha256,
        ).hexdigest()
    )
    if not signature or not hmac.compare_digest(expected, signature):
        return ("Firma inválida", 403)

    try:
        payload = json.loads(raw_body)
    except ValueError:
        return ("JSON inválido", 400)

    if message_type == "webhook_callback_verification":
        # Twitch valida que este endpoint es realmente nuestro respondiendo
        # con el "challenge" tal cual, en texto plano, al crear cada
        # suscripción.
        return (payload.get("challenge", ""), 200, {"Content-Type": "text/plain"})

    if message_type == "revocation":
        sub = payload.get("subscription", {})
        print(
            f"[WARN] Twitch revocó una suscripción EventSub: "
            f"type={sub.get('type')} status={sub.get('status')} condition={sub.get('condition')}"
        )
        return ("", 200)

    if message_type == "notification":
        sub_type = payload.get("subscription", {}).get("type", "")
        event = payload.get("event", {})
        try:
            handle_twitch_eventsub_notification(sub_type, event)
        except Exception as e:
            # Nunca devolver un error 5xx por un fallo nuestro al procesar
            # el evento -- Twitch reintentaría (y reintentaría) la misma
            # notificación indefinidamente. Se registra y se responde 200.
            print(f"[WARN] Error procesando notificación EventSub ({sub_type}): {e}")
        return ("", 200)

    return ("", 200)


# ------------------------------------------------------------------
# Vista de configuración del módulo de Twitch (notificaciones de directos)
# ------------------------------------------------------------------
@app.route("/twitch")
@requires_module("twitch")
def twitch_config():
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    try:
        config = safe_get_config()
        bot_token = active_bot_token(config)
        channels = fetch_guild_channels(guild_id, bot_token, types=(0, 5))
        roles = fetch_guild_roles(guild_id, bot_token)

        if not channels or not roles:
            flash(
                "No se pudieron cargar todos los canales/roles de ese servidor. "
                "Verifica que el bot esté invitado y tenga permisos.",
                "error",
            )

        return render_template(
            "twitch.html",
            config=config,
            variables=TWITCH_VARIABLES,
            channels=channels,
            roles=roles,
            guild_id=guild_id,
            user=current_user(),
        )
    except Exception as e:
        flash(f"No se pudo cargar la configuración de Twitch: {e}", "error")
        return redirect(url_for("index"))


@app.route("/twitch/save", methods=["POST"])
@requires_module("twitch")
def save_twitch():
    """
    Guarda "live" y "credentials" usando notación de punto (twitch.live /
    twitch.credentials) para NO tocar twitch.notified_ids -- ese campo es
    estado gestionado por el bot (directos ya notificados) y debe
    sobrevivir a cualquier guardado desde el dashboard.

    "channel" se guarda TAL CUAL lo escribe el usuario (URL completa o
    nombre de usuario) -- solo se le quita espacios en blanco. No se parsea
    ni se valida el formato aquí: es el bot (cogs/twitch.py) quien debe
    normalizar el valor y extraer el nombre de canal real antes de
    consultar la API de Twitch.

    Las credenciales de la app de Twitch (Client ID/Secret) NO se tocan
    aquí -- se gestionan exclusivamente desde el módulo "Logs Twitch"
    (save_twitch_logs), aunque técnicamente vivan en el mismo campo
    config.twitch.credentials.
    """
    form = request.form

    live = {
        "enabled": "live_enabled" in form,
        "channel": form.get("live_channel", "").strip(),
        "discord_channel_id": form.get("live_discord_channel_id", "").strip(),
        "ping_role_id": form.get("live_ping_role_id", "").strip(),
        "mensaje": form.get("live_mensaje", "").strip(),
    }

    try:
        save_fields({"twitch.live": live})
        flash("Configuración de Twitch guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("twitch_config"))


# ------------------------------------------------------------------
# Vista de configuración de "Logs Twitch" -- MÓDULO INDEPENDIENTE de
# "Twitch" (notificaciones de directo): licencia propia
# (allowed_modules.twitch_logs), switch propio (modules.twitch_logs) y
# tarjeta propia en modules.html. Las credenciales de la app de Twitch
# (Client ID/Secret, config.twitch.credentials) se configuran EXCLUSIVAMENTE
# aquí, aunque el campo en Mongo sea compartido con "twitch" -- son
# necesarias para el OAuth y para crear las suscripciones EventSub, no
# para las notificaciones de directo.
# ------------------------------------------------------------------
@app.route("/twitch/logs")
@requires_module("twitch_logs")
def twitch_logs_config():
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    try:
        config = safe_get_config()
        bot_token = active_bot_token(config)
        channels = fetch_guild_channels(guild_id, bot_token, types=(0, 5))

        if not channels:
            flash(
                "No se pudieron cargar los canales de ese servidor. "
                "Verifica que el bot esté invitado y tenga permisos.",
                "error",
            )

        return render_template(
            "logtwitch.html",
            config=config,
            channels=channels,
            guild_id=guild_id,
            user=current_user(),
        )
    except Exception as e:
        flash(f"No se pudo cargar la configuración de Logs de Twitch: {e}", "error")
        return redirect(url_for("index"))


@app.route("/twitch/logs/save", methods=["POST"])
@requires_module("twitch_logs")
def save_twitch_logs():
    """
    Guarda el canal de Discord, los toggles de filtro y las credenciales de
    la app de Twitch (Client ID/Secret) de los logs de sanciones. NUNCA toca
    broadcaster_id/broadcaster_login/broadcaster_display_name/
    available_channels/access_token/refresh_token/subscription_ids -- esos
    los gestiona exclusivamente el flujo OAuth y el selector de canal
    (twitch_oauth_login/twitch_oauth_callback/select_twitch_channel), nunca
    este formulario.

    "client_secret" es la credencial sensible de la app de Twitch de ESTE
    cliente: se cifra con encrypt_secret() antes de guardarla (ver
    SENSITIVE_CONFIG_PATHS). El campo del formulario llega vacío si el
    usuario no ha tocado el campo de contraseña -- en ese caso se conserva
    el secreto que ya hubiera guardado, en vez de borrarlo.
    """
    form = request.form
    config = safe_get_config()

    log_channel_id = form.get("twitch_log_channel_id", "").strip()
    filters = {
        "ban": "twitch_filter_ban" in form,
        "timeout": "twitch_filter_timeout" in form,
        "warning": "twitch_filter_warning" in form,
        "delete_message": "twitch_filter_delete_message" in form,
    }

    new_client_secret = form.get("twitch_client_secret", "").strip()
    current_client_secret = config.get("twitch", {}).get("credentials", {}).get("client_secret", "")
    credentials = {
        "client_id": form.get("twitch_client_id", "").strip(),
        "client_secret": encrypt_secret(new_client_secret or current_client_secret),
    }

    try:
        save_fields({
            "twitch.log_channel_id": log_channel_id,
            "twitch.filters": filters,
            "twitch.credentials": credentials,
        })
        flash("Configuración de logs de Twitch guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("twitch_logs_config"))


# ------------------------------------------------------------------
# Sistema de Seguridad Profesional "WickSecurity" -- Anti-Raid (BETA)
# (AutoMod, AntiNuke, Cuarentena, JoinGate, Whitelists) -- estilo WickBot.
# ------------------------------------------------------------------
@app.route("/security-wick")
@requires_module("wick_security")
def wick_security_config():
    guild_id = current_guild_id()
    if not guild_id:
        flash("Selecciona un servidor antes de continuar.", "error")
        return redirect(url_for("index"))

    try:
        config = safe_get_config()
        bot_token = active_bot_token(config)
        channels = fetch_guild_channels(guild_id, bot_token, types=(0, 5))
        categories = fetch_guild_channels(guild_id, bot_token, types=(4,))
        roles = fetch_guild_roles(guild_id, bot_token)

        if not channels or not roles:
            flash(
                "No se pudieron cargar todos los canales/roles de ese servidor. "
                "Verifica que el bot esté invitado y tenga permisos.",
                "error",
            )

        return render_template(
            "wick_security.html",
            config=config,
            joingate_actions=JOINGATE_ACTIONS,
            channels=channels,
            categories=categories,
            roles=roles,
            guild_id=guild_id,
        )
    except Exception as e:
        flash(f"No se pudo cargar la configuración de Seguridad Pro: {e}", "error")
        return redirect(url_for("index"))


@app.route("/security-wick/misc/save", methods=["POST"])
@requires_module("wick_security")
def save_wick_misc():
    """Paso 1 (Misc): canal de logs generales, canal de logs de moderación y rol principal/verificado."""
    form = request.form
    misc = {
        "log_channel_id": form.get("log_channel_id", "").strip(),
        "mod_log_channel_id": form.get("mod_log_channel_id", "").strip(),
        "main_role_id": form.get("main_role_id", "").strip(),
    }

    try:
        save_fields({"misc": misc})
        flash("Configuración general (Misc) guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("wick_security_config") + "#misc")


@app.route("/security-wick/automod/save", methods=["POST"])
@requires_module("wick_security")
def save_wick_automod():
    """
    Paso 2 (AutoMod & Anti-Spam). El switch principal de este paso
    ("automod_enabled") sincroniza a la vez automod.enabled y
    modules.automod, igual que el resto de módulos con toggle propio.
    """
    form = request.form
    enabled = "automod_enabled" in form

    anti_spam = {
        "enabled": "anti_spam_enabled" in form,
        "mention_spam": "mention_spam" in form,
        "attachment_spam": "attachment_spam" in form,
        "repetitive_spam": "repetitive_spam" in form,
        "long_messages": "long_messages" in form,
        "emoji_spam": "emoji_spam" in form,
        "new_lines_spam": "new_lines_spam" in form,
        "zalgo_spam": "zalgo_spam" in form,
    }
    automod = {
        "enabled": enabled,
        "moderate_invites": "moderate_invites" in form,
        "filter_nsfw": "filter_nsfw" in form,
        "filter_scam": "filter_scam" in form,
        "anti_spam": anti_spam,
        "monitor_webhooks": "monitor_webhooks" in form,
    }

    try:
        save_fields({"automod": automod, "modules.automod": enabled})
        flash("Configuración de AutoMod guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("wick_security_config") + "#automod")


@app.route("/security-wick/antinuke/save", methods=["POST"])
@requires_module("wick_security")
def save_wick_antinuke():
    """
    Paso 3 (AntiNuke & Cuarentena). Ambos bloques comparten un mismo paso en
    la UI, pero se guardan en dos campos independientes de MongoDB
    (antinuke / quarantine) con sus propios switches "enabled" sincronizados
    a modules.antinuke / modules.quarantine.
    """
    form = request.form
    antinuke_enabled = "antinuke_enabled" in form
    quarantine_enabled = "quarantine_enabled" in form

    antinuke = {
        "enabled": antinuke_enabled,
        "monitor_kicks_bans": "monitor_kicks_bans" in form,
        "monitor_role_creates": "monitor_role_creates" in form,
        "monitor_role_deletes": "monitor_role_deletes" in form,
        "monitor_channel_creates": "monitor_channel_creates" in form,
        "monitor_channel_deletes": "monitor_channel_deletes" in form,
        "monitor_webhook_creates": "monitor_webhook_creates" in form,
        "monitor_webhook_deletes": "monitor_webhook_deletes" in form,
    }
    quarantine = {
        "enabled": quarantine_enabled,
        "punish_unauthorized_admins_perms": "punish_unauthorized_admins_perms" in form,
        "punish_unauthorized_admins_members": "punish_unauthorized_admins_members" in form,
        "protect_everyone_main_roles": "protect_everyone_main_roles" in form,
        "guard_vanity_url": "guard_vanity_url" in form,
        "quarantine_role_id": form.get("quarantine_role_id", "").strip(),
    }

    try:
        save_fields(
            {
                "antinuke": antinuke,
                "quarantine": quarantine,
                "modules.antinuke": antinuke_enabled,
                "modules.quarantine": quarantine_enabled,
            }
        )
        flash("Configuración de AntiNuke y Cuarentena guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("wick_security_config") + "#antinuke")


@app.route("/security-wick/whitelists/save", methods=["POST"])
@requires_module("wick_security")
def save_wick_whitelists():
    """
    Paso 4 (Whitelists). Cada grupo (spam/invites/pings/everyone) tiene 5
    campos de entidad (members/roles/channels/categories/webhooks), todos
    enviados como IDs separados por comas en un input oculto/de texto con
    name="wl_<grupo>_<tipo>" -- mismo patrón que el resto del dashboard usa
    para roles (staff_roles, autoroles_ids, etc).
    """
    form = request.form

    def _parse_ids(field_name):
        raw = form.get(field_name, "")
        return [v.strip() for v in raw.split(",") if v.strip()]

    whitelists = {}
    for group_name in ("spam", "invites", "pings", "everyone"):
        whitelists[group_name] = {
            entity_type: _parse_ids(f"wl_{group_name}_{entity_type}")
            for entity_type in DEFAULT_WHITELIST_GROUP
        }
    whitelists["channel_creation_categories"] = _parse_ids("wl_channel_creation_categories")
    whitelists["quarantine_users"] = _parse_ids("wl_quarantine_users")

    try:
        save_fields({"whitelists": whitelists})
        flash("Listas blancas guardadas correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("wick_security_config") + "#whitelists")


@app.route("/security-wick/joingate/save", methods=["POST"])
@requires_module("wick_security")
def save_wick_joingate():
    """Paso 5 (JoinGate): filtros aplicados a cada nuevo miembro que entra al servidor."""
    form = request.form

    def _parse_int(field, default, minimum=0):
        raw = (form.get(field, "") or "").strip()
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return default
        return value if value >= minimum else default

    enabled = "joingate_enabled" in form

    action = form.get("action", DEFAULT_JOINGATE_CONFIG["action"]).strip()
    if action not in JOINGATE_ACTIONS:
        action = DEFAULT_JOINGATE_CONFIG["action"]

    joingate = {
        "enabled": enabled,
        "target_unauthorized_bots": "target_unauthorized_bots" in form,
        "target_young_accounts": "target_young_accounts" in form,
        "min_account_age_hours": _parse_int(
            "min_account_age_hours", DEFAULT_JOINGATE_CONFIG["min_account_age_hours"], minimum=0
        ),
        "target_no_pfp": "target_no_pfp" in form,
        "target_unverified_bots": "target_unverified_bots" in form,
        "target_invite_in_name": "target_invite_in_name" in form,
        "target_suspicious_nicks": "target_suspicious_nicks" in form,
        "action": action,
    }

    try:
        save_fields({"joingate": joingate, "modules.joingate": enabled})
        flash("Configuración de JoinGate guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("wick_security_config") + "#joingate")


# ------------------------------------------------------------------
# Panel de Administración (SaaS multi-tenant) -- exclusivo de ADMIN_DISCORD_ID
# ------------------------------------------------------------------
@app.route("/admin")
@requires_admin
def admin_panel():
    """Lista todos los bots/clientes del sistema con su licencia actual."""
    docs = []
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
    else:
        try:
            docs = list(config_collection.find({}))
        except Exception as e:
            flash(f"No se pudo leer la lista de bots desde MongoDB: {e}", "error")
            docs = []

    # Estado de bloqueo de cada cliente (users_collection.blocked), indexado
    # por discord_user_id para no hacer una consulta por bot en el bucle.
    blocked_by_discord_id = {}
    discord_ids = [doc.get("discord_user_id") for doc in docs if doc.get("discord_user_id")]
    if discord_ids and mongo_ready():
        try:
            for u in users_collection.find({"_id": {"$in": discord_ids}}, {"blocked": 1}):
                blocked_by_discord_id[u["_id"]] = bool(u.get("blocked"))
        except Exception as e:
            print(f"[WARN] admin_panel() users_collection.find: {e}")

    bots = []
    for doc in docs:
        allowed = doc.get("allowed_modules")
        if not isinstance(allowed, dict):
            allowed = {}

        # Canales del servidor de ESTE cliente, para el selector del aviso
        # de "bot conectado" -- se usa SIEMPRE el bot_token propio de este
        # cliente (nunca el del admin), porque el mensaje tiene que salir
        # literalmente desde su bot, que es el que está en su servidor.
        guild_id = doc.get("guild_id") or ""
        notify_channels = []
        if guild_id:
            try:
                bot_token_for_notify = decrypt_secret(doc.get("bot_token")) or DISCORD_BOT_TOKEN
                notify_channels = fetch_guild_channels(guild_id, bot_token_for_notify, types=(0, 5)) or []
            except Exception as e:
                print(f"[WARN] admin_panel() no se pudieron cargar canales de {doc.get('_id')}: {e}")
                notify_channels = []

        bots.append(
            {
                "id": doc.get("_id"),
                "bot_name": doc.get("bot_name") or "",
                "discord_user_id": doc.get("discord_user_id") or "",
                "guild_id": guild_id,
                "client_id": doc.get("client_id") or "",
                "has_token": bool(doc.get("bot_token")),
                "allowed_modules": {
                    mod["key"]: allowed.get(mod["key"], True) for mod in LICENSABLE_MODULES
                },
                "blocked": blocked_by_discord_id.get(doc.get("discord_user_id"), False),
                "notify_channels": notify_channels,
            }
        )

    return render_template(
        "admin.html",
        bots=bots,
        licensable_modules=LICENSABLE_MODULES,
        user=current_user(),
        admin_personal_bot_id=ADMIN_PERSONAL_BOT_ID,
    )


@app.route("/admin/bots/create", methods=["POST"])
@requires_admin
def admin_create_bot():
    """Crea (vincula) un nuevo bot/cliente: genera un bot_id, guarda sus
    credenciales y licencia, y asocia el Discord ID del cliente a ese bot_id
    en users_collection."""
    discord_user_id = request.form.get("discord_user_id", "").strip()
    bot_token = request.form.get("bot_token", "").strip()
    client_id = request.form.get("client_id", "").strip()
    bot_name = request.form.get("bot_name", "").strip()

    if not discord_user_id:
        flash("Indica el ID de Discord del cliente.", "error")
        return redirect(url_for("admin_panel"))

    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    allowed_modules = {
        mod["key"]: (request.form.get(f"module_{mod['key']}") == "on")
        for mod in LICENSABLE_MODULES
    }

    bot_id = secrets.token_hex(8)
    new_bot = dict(DEFAULT_CONFIG)
    new_bot["_id"] = bot_id
    new_bot["bot_name"] = bot_name
    new_bot["discord_user_id"] = discord_user_id
    # Cifrado: el token del bot del cliente es una credencial sensible (da
    # control total sobre su bot de Discord) -- nunca se guarda en texto
    # plano. get_config() lo descifra automáticamente al leerlo.
    new_bot["bot_token"] = encrypt_secret(bot_token)
    new_bot["client_id"] = client_id
    new_bot["allowed_modules"] = allowed_modules

    try:
        config_collection.insert_one(new_bot)
        users_collection.update_one(
            {"_id": discord_user_id},
            {"$set": {"bot_id": bot_id}},
            upsert=True,
        )
        flash(f"Bot creado y vinculado correctamente (bot_id: {bot_id}).", "success")
    except Exception as e:
        flash(f"Error al crear el bot en MongoDB: {e}", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/bots/<bot_id>/license", methods=["POST"])
@requires_admin
def admin_update_license(bot_id):
    """Bloquea/desbloquea módulos en tiempo real para un bot/cliente concreto."""
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    allowed_modules = {
        mod["key"]: (request.form.get(f"module_{mod['key']}") == "on")
        for mod in LICENSABLE_MODULES
    }

    try:
        result = config_collection.update_one(
            {"_id": bot_id}, {"$set": {"allowed_modules": allowed_modules}}
        )
        if result.matched_count == 0:
            flash("Ese bot no existe.", "error")
        else:
            flash("Licencia de módulos actualizada correctamente.", "success")
    except Exception as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/bots/<bot_id>/rename", methods=["POST"])
@requires_admin
def admin_update_bot_name(bot_id):
    """
    Renombra un bot ya creado (bot_name en config_collection). bot_name solo
    se pedía hasta ahora en el formulario de creación -- esta ruta permite
    corregirlo después sin tener que borrar y recrear el bot, por ejemplo
    para quitar nombres de prueba ("pruebaaa bot") que quedaron guardados
    de pruebas antiguas y que se muestran tal cual en el home del cliente
    (modules.html usa {{ config.bot_name }}).
    """
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    new_name = request.form.get("bot_name", "").strip()

    try:
        result = config_collection.update_one(
            {"_id": bot_id}, {"$set": {"bot_name": new_name}}
        )
        if result.matched_count == 0:
            flash("Ese bot no existe.", "error")
        else:
            flash("Nombre del bot actualizado correctamente.", "success")
    except Exception as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/bots/<bot_id>/notify", methods=["POST"])
@requires_admin
def admin_notify_bot_connected(bot_id):
    """
    Envía un embed verde de "bot conectado con el dashboard" al canal que
    elija el admin, usando el bot_token PROPIO de ese cliente -- nunca el
    del admin, porque el admin no tiene acceso directo al servidor del
    cliente, solo a su configuración en Mongo. Es un simple POST vía la API
    REST de Discord (mismo patrón que send_discord_log_embed): confirma que
    el bot_token guardado es válido y tiene permiso para escribir en ese
    canal, no que el proceso del bot (discord.py) esté conectado en este
    instante -- eso son cosas independientes en Discord.
    """
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    channel_id = request.form.get("channel_id", "").strip()
    if not channel_id:
        flash("Selecciona un canal antes de enviar el aviso.", "error")
        return redirect(url_for("admin_panel"))

    doc = config_collection.find_one({"_id": bot_id})
    if not doc:
        flash("Ese bot no existe.", "error")
        return redirect(url_for("admin_panel"))

    bot_token = decrypt_secret(doc.get("bot_token")) or DISCORD_BOT_TOKEN
    embed = {
        "title": "✅ Bot conectado con el dashboard",
        "description": "Este mensaje confirma que el bot puede recibir y aplicar la configuración del panel de administración.",
        "color": 0x23A55A,  # verde
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        send_discord_log_embed(bot_token, channel_id, embed)
        flash(f"Aviso de conexión enviado al canal seleccionado ({doc.get('bot_name') or bot_id}).", "success")
    except requests.RequestException as e:
        flash(f"No se pudo enviar el aviso a Discord: {e}", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/bots/<bot_id>/access", methods=["POST"])
@requires_admin
def admin_update_client_access(bot_id):
    """
    Bloquea/desbloquea el acceso del cliente dueño de este bot al dashboard
    (whitelist/bloqueo de login). Escribe en users_collection, indexada por
    discord_user_id, no en config_collection -- current_bot_id() consulta
    este mismo campo en cada request vía is_user_blocked(), así que un
    bloqueo aplica de inmediato, incluso si el cliente ya tenía sesión
    iniciada.
    """
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    try:
        bot_doc = config_collection.find_one({"_id": bot_id}, {"discord_user_id": 1})
    except Exception as e:
        flash(f"No se pudo leer ese bot desde MongoDB: {e}", "error")
        return redirect(url_for("admin_panel"))

    if not bot_doc:
        flash("Ese bot no existe.", "error")
        return redirect(url_for("admin_panel"))

    discord_user_id = bot_doc.get("discord_user_id")
    if not discord_user_id:
        flash("Ese bot no tiene un ID de Discord de cliente asociado todavía.", "error")
        return redirect(url_for("admin_panel"))

    blocked = request.form.get("blocked") == "on"

    try:
        # $setOnInsert conserva el bot_id existente si el documento ya
        # existía -- esta ruta solo debe tocar el campo "blocked".
        users_collection.update_one(
            {"_id": discord_user_id},
            {"$set": {"blocked": blocked}, "$setOnInsert": {"bot_id": bot_id}},
            upsert=True,
        )
        flash(
            "Acceso del cliente bloqueado correctamente." if blocked
            else "Acceso del cliente restaurado correctamente.",
            "success",
        )
    except Exception as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/bots/<bot_id>/delete", methods=["POST"])
@requires_admin
def admin_delete_bot(bot_id):
    """
    Elimina por completo un bot/cliente que ya no se usa: borra su
    documento de config_collection y desvincula (elimina) cualquier
    entrada de users_collection que todavía apunte a él, para que no queden
    vínculos antiguos colgando. No se puede eliminar el bot personal del
    administrador.
    """
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    if bot_id == ADMIN_PERSONAL_BOT_ID:
        flash("No puedes eliminar el bot personal del administrador.", "error")
        return redirect(url_for("admin_panel"))

    try:
        result = config_collection.delete_one({"_id": bot_id})
        unlinked = users_collection.delete_many({"bot_id": bot_id})
        if result.deleted_count == 0:
            flash("Ese bot no existe.", "error")
        else:
            flash(
                f"Bot eliminado correctamente. Se desvincularon "
                f"{unlinked.deleted_count} acceso(s) de cliente asociado(s).",
                "success",
            )
    except Exception as e:
        flash(f"Error al eliminar en MongoDB: {e}", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/simulate/<bot_id>", methods=["POST"])
@requires_admin
def admin_simulate(bot_id):
    """
    Activa el "Modo Vista Previa": el admin pasa a ver/editar el dashboard
    exactamente como lo vería el cliente dueño de `bot_id`, respetando su
    licencia (allowed_modules). Se guarda en sesión, no se toca MongoDB.
    """
    if not mongo_ready():
        flash("La conexión a MongoDB no está disponible en este momento.", "error")
        return redirect(url_for("admin_panel"))

    try:
        target = config_collection.find_one({"_id": bot_id})
    except Exception as e:
        flash(f"No se pudo leer ese bot desde MongoDB: {e}", "error")
        return redirect(url_for("admin_panel"))

    if not target:
        flash("Ese bot no existe.", "error")
        return redirect(url_for("admin_panel"))

    session["active_bot_id"] = bot_id
    session["is_simulating"] = True
    # El admin probablemente no es miembro del servidor del cliente, así que
    # no podemos fiarnos de session["discord_guilds"] (su propia lista de
    # servidores) -- usamos directamente el guild_id ya guardado en la config
    # de ESE bot.
    session["guild_id"] = target.get("guild_id", "")

    flash(f"Simulando la vista del bot: {target.get('bot_name') or bot_id}.", "success")
    return redirect(url_for("index"))


@app.route("/admin/stop-simulation", methods=["POST", "GET"])
@requires_admin
def admin_stop_simulation():
    """Sale del Modo Vista Previa y devuelve al admin a su propio bot."""
    session["active_bot_id"] = ADMIN_PERSONAL_BOT_ID
    session.pop("is_simulating", None)
    session.pop("guild_id", None)
    return redirect(url_for("admin_panel"))


# ------------------------------------------------------------------
# Editor de plantillas de embed de los logs de sanciones de Twitch --
# EXCLUSIVO del admin del SaaS. Un cliente jamás puede llegar aquí: ambas
# rutas están detrás de @requires_admin, no de @requires_module, y el
# documento que leen/escriben (settings_collection) es global, no cuelga de
# ningún bot_id ni aparece en ninguna vista de cliente.
# ------------------------------------------------------------------
@app.route("/admin/twitch-embeds")
@requires_admin
def admin_twitch_embeds():
    templates = get_twitch_embed_templates()
    return render_template(
        "admin_twitch_embeds.html",
        templates=templates,
        variables=TWITCH_EMBED_VARIABLES,
        labels=TWITCH_EMBED_LABELS,
        defaults=DEFAULT_TWITCH_EMBED_TEMPLATES,
        user=current_user(),
    )


@app.route("/admin/twitch-embeds/save", methods=["POST"])
@requires_admin
def save_admin_twitch_embeds():
    if settings_collection is None:
        flash("MongoDB no disponible: no se pudo guardar.", "error")
        return redirect(url_for("admin_twitch_embeds"))

    form = request.form
    update = {}
    for key, default_tpl in DEFAULT_TWITCH_EMBED_TEMPLATES.items():
        update[key] = {
            "title": form.get(f"{key}_title", "").strip(),
            "description": form.get(f"{key}_description", "").strip(),
            "color": form.get(f"{key}_color", "").strip().lstrip("#") or default_tpl["color"],
            "footer": form.get(f"{key}_footer", "").strip(),
        }

    try:
        settings_collection.update_one(
            {"_id": TWITCH_EMBED_TEMPLATES_ID}, {"$set": update}, upsert=True
        )
        flash("Plantillas de embeds de Twitch guardadas correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("admin_twitch_embeds"))


# Vercel usa esta variable "app" como punto de entrada WSGI (nunca ejecuta
# este bloque __main__, así que debug=True aquí solo afecta cuando corres
# `python app.py` a mano). El modo debug se desactiva automáticamente si
# APP_ENV=production, para no exponer el debugger interactivo de Flask ni
# tracebacks con datos sensibles en el dominio de clientes.
if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)
