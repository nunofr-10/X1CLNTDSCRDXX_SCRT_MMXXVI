import os
import secrets
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

DEFAULT_TWITCH_CONFIG = {
    # IDs de directos ya notificados, para que el bot no repita el aviso.
    # Es estado gestionado por el bot, no por el dashboard: al guardar
    # desde la web (save_twitch) nunca se sobrescribe este campo.
    "notified_ids": [],
    "live": dict(DEFAULT_TWITCH_LIVE),
    "credentials": dict(DEFAULT_TWITCH_CREDENTIALS),
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


def get_config():
    """
    Obtiene la configuración del bot/cliente activo de la sesión (bot_id =
    current_bot_id()) desde MongoDB, rellenando defaults.

    Si no hay ningún bot activo en la sesión (usuario sin acceso, o no
    logueado), devuelve DEFAULT_CONFIG tal cual -- las vistas que dependen de
    un bot real deben comprobar current_bot_id() / current_user() antes de
    fiarse de que esta config corresponde a un cliente de verdad.
    """
    bot_id = current_bot_id()
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
    merged["twitch"] = {
        "notified_ids": list(twitch_notified_ids) if isinstance(twitch_notified_ids, list) else [],
        "live": {**DEFAULT_TWITCH_LIVE, **_dict_field(stored_twitch, "live")},
        "credentials": {
            **DEFAULT_TWITCH_CREDENTIALS,
            **_dict_field(stored_twitch, "credentials"),
        },
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
        return render_template("no_access.html", user=user)

    try:
        config = safe_get_config()
        return render_template(
            "modules.html",
            tickets_module=TICKETS_MODULE,
            moderation_module=MODERATION_MODULE,
            youtube_module=YOUTUBE_MODULE,
            twitch_module=TWITCH_MODULE,
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
            wick_security_module=WICK_SECURITY_MODULE,
            config=dict(DEFAULT_CONFIG),
            user=current_user(),
            guilds=session.get("discord_guilds", []),
            guild_id=current_guild_id(),
        )


@app.route("/no-access")
def no_access():
    """
    Página mostrada a un cliente logueado que todavía no tiene ningún bot
    asignado (no existe en users_collection, o su bot_id no resolvió a
    ningún documento). Es el destino de url_for("no_access") usado por los
    decoradores requires_login/requires_module cuando current_bot_id() es
    None.
    """
    return render_template("no_access.html", user=current_user())


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

    "client_secret" es la credencial sensible de la app de Twitch de ESTE
    cliente: se cifra con encrypt_secret() antes de guardarla (ver
    SENSITIVE_CONFIG_PATHS). El campo del formulario llega vacío si el
    usuario no ha tocado el campo de contraseña -- en ese caso se conserva
    el secreto que ya hubiera guardado, en vez de borrarlo.
    """
    form = request.form
    config = safe_get_config()

    live = {
        "enabled": "live_enabled" in form,
        "channel": form.get("live_channel", "").strip(),
        "discord_channel_id": form.get("live_discord_channel_id", "").strip(),
        "ping_role_id": form.get("live_ping_role_id", "").strip(),
        "mensaje": form.get("live_mensaje", "").strip(),
    }

    new_client_secret = form.get("twitch_client_secret", "").strip()
    current_client_secret = config.get("twitch", {}).get("credentials", {}).get("client_secret", "")
    credentials = {
        "client_id": form.get("twitch_client_id", "").strip(),
        "client_secret": encrypt_secret(new_client_secret or current_client_secret),
    }

    try:
        save_fields({"twitch.live": live, "twitch.credentials": credentials})
        flash("Configuración de Twitch guardada correctamente.", "success")
    except PyMongoError as e:
        flash(f"Error al guardar en MongoDB: {e}", "error")

    return redirect(url_for("twitch_config"))


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
        bots.append(
            {
                "id": doc.get("_id"),
                "bot_name": doc.get("bot_name") or "",
                "discord_user_id": doc.get("discord_user_id") or "",
                "guild_id": doc.get("guild_id") or "",
                "client_id": doc.get("client_id") or "",
                "has_token": bool(doc.get("bot_token")),
                "allowed_modules": {
                    mod["key"]: allowed.get(mod["key"], True) for mod in LICENSABLE_MODULES
                },
                "blocked": blocked_by_discord_id.get(doc.get("discord_user_id"), False),
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


# Vercel usa esta variable "app" como punto de entrada WSGI (nunca ejecuta
# este bloque __main__, así que debug=True aquí solo afecta cuando corres
# `python app.py` a mano). El modo debug se desactiva automáticamente si
# APP_ENV=production, para no exponer el debugger interactivo de Flask ni
# tracebacks con datos sensibles en el dominio de clientes.
if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)
