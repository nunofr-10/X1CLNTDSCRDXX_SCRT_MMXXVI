# Entornos (dev/producción) y cifrado de datos sensibles

Guía de referencia para lo implementado en esta sesión. No hace falta tocar rutas de Flask: todo se controla con variables de entorno, configuradas de forma independiente en cada despliegue de Vercel.

## 1. Separación de entornos

### Arquitectura recomendada

Dos despliegues de Vercel a partir del mismo repositorio, cada uno con su propio dominio y sus propias variables de entorno:

- **Despliegue de pruebas** (tu dominio actual): lo que usas para desarrollar y probar cambios.
- **Despliegue de clientes** (dominio nuevo/oficial): el que vas a crear ahora, apuntando a la configuración real de producción.

No son ramas de código distintas ni requieren lógica condicional de rutas: es el mismo `app.py`, desplegado dos veces, con `APP_ENV` y el resto de variables configuradas distinto en cada proyecto de Vercel.

### Archivos que se tocaron

- `app.py`: nuevas variables `APP_ENV`, `MONGO_DB_NAME`, `ENCRYPTION_KEY` (sección 2), cookies de sesión seguras en producción, `debug` desactivado en producción.
- `cogs/moderation.py`, `cogs/security_wick.py`: ahora leen `MONGO_DB_NAME` en vez de tener `"discord_bot"` fijo en el código.

### Variables de entorno a configurar en CADA despliegue

| Variable | Despliegue de pruebas | Despliegue de clientes (producción) |
|---|---|---|
| `APP_ENV` | `development` | `production` |
| `SECRET_KEY` | cualquier valor de prueba | valor único y secreto (ver abajo cómo generarlo) |
| `MONGO_URI` | tu cluster de Mongo | el mismo cluster o uno separado, tu decisión |
| `MONGO_DB_NAME` | `discord_bot_dev` (recomendado) | `discord_bot` (o el nombre que ya usan tus clientes reales) |
| `DISCORD_CLIENT_ID` | app de Discord de pruebas (recomendado) o la misma | app de Discord oficial |
| `DISCORD_CLIENT_SECRET` | según lo anterior | según lo anterior |
| `DISCORD_BOT_TOKEN` | token de tu bot de pruebas | token del bot personal del admin en producción |
| `DISCORD_REDIRECT_URI` | `https://tu-dominio-dev.vercel.app/callback` | `https://tu-dominio-clientes.com/callback` |
| `ADMIN_DISCORD_ID` | tu ID de Discord | tu ID de Discord |
| `ADMIN_PERSONAL_BOT_ID` | déjalo vacío (usa `bot_config` por defecto) | igual |
| `ENCRYPTION_KEY` | clave Fernet de pruebas | clave Fernet de producción (**distinta** a la de dev) |

Puntos importantes:

- **`MONGO_DB_NAME` es la pieza clave para no mezclar datos**: si pruebas y producción comparten el mismo cluster de Mongo Atlas pero usan nombres de base de datos distintos (`discord_bot_dev` vs `discord_bot`), tus pruebas nunca van a tocar configuración de clientes reales, aunque te equivoques de `MONGO_URI`.
- **`DISCORD_REDIRECT_URI` debe coincidir exactamente** con una de las "Redirect URIs" registradas en el Portal de Desarrolladores de Discord de la aplicación que uses (Developer Portal → tu app → OAuth2 → Redirects). Si usas la misma app de Discord para ambos entornos, añade AMBAS URLs de callback ahí. Si usas apps de Discord separadas (recomendado para no mezclar bots de prueba con el oficial), cada una tiene su propio `DISCORD_CLIENT_ID`/`DISCORD_CLIENT_SECRET`/lista de redirects.
- El bot de Discord (`main.py` + `cogs/`) es un proceso aparte del dashboard Flask. Si vas a tener un bot de pruebas Y un bot oficial corriendo, cada proceso necesita su propio `.env` con `DISCORD_BOT_TOKEN` y (opcionalmente) `MONGO_DB_NAME` distintos.

### Generar un `SECRET_KEY` seguro

```
python -c "import secrets; print(secrets.token_hex(32))"
```

## 2. Modelo multi-tenant: aislamiento por cliente + cifrado generalizado

### Aislamiento de datos (ya existía, reforzado aquí)

Cada bot/cliente es un documento independiente en `config_collection`, indexado por su propio `bot_id`. `current_bot_id()` resuelve, en cada request, a qué bot pertenece la sesión activa (cliente logueado, admin en su bot personal, o admin simulando a un cliente concreto), y **todas** las lecturas/escrituras (`get_config()`, `save_fields()`, y las llamadas a la API de Discord vía `active_bot_token()`) pasan por ese `bot_id` -- nunca hay una variable global compartida entre clientes para sus credenciales o configuración. Esto ya estaba así desde la conversión a SaaS multi-tenant; en esta vuelta se generalizó el cifrado y se añadió un segundo ejemplo real (Twitch) para confirmarlo.

### Registro central de campos sensibles: `SENSITIVE_CONFIG_PATHS`

En vez de tener una línea de `decrypt_secret()` escrita a mano por cada campo sensible dentro de `get_config()`, ahora existe un catálogo único en `app.py`:

```python
SENSITIVE_CONFIG_PATHS = [
    "bot_token",
    "twitch.credentials.client_secret",
]
```

`get_config()` llama una sola vez a `decrypt_sensitive_fields(merged)` al final, que recorre esta lista y descifra cada ruta presente en el documento del bot activo (usando notación de punto para campos anidados, ej. `twitch.credentials.client_secret`). El resultado: el resto del código (`active_bot_token()`, la futura llamada a la API de Twitch, etc.) siempre recibe texto plano listo para usar, y solo para el bot/cliente de la sesión activa -- nunca se mezcla con el de otro.

### Qué se cifra ahora mismo

| Campo | Ruta en el documento | Motivo |
|---|---|---|
| Token del bot de Discord del cliente | `bot_token` | Control total sobre su bot de Discord |
| Client Secret de la app de Twitch del cliente | `twitch.credentials.client_secret` | Credencial de su app registrada en la Twitch Developer Console |

`twitch.credentials.client_id` **no** se cifra (es un identificador público, igual que `client_id` de Discord) -- solo el secret.

### Archivos que se tocaron

- **`app.py`**:
  - `SENSITIVE_CONFIG_PATHS`, `_get_by_path()`, `_set_by_path()`, `decrypt_sensitive_fields()` -- el mecanismo genérico.
  - `DEFAULT_TWITCH_CREDENTIALS` + `DEFAULT_TWITCH_CONFIG["credentials"]` -- nuevo bloque `client_id`/`client_secret` por cliente.
  - `get_config()`: el merge de Twitch ahora incluye `credentials`; al final llama a `decrypt_sensitive_fields(merged)` en vez de descifrar `bot_token` a mano.
  - `admin_create_bot()`: sigue cifrando `bot_token` con `encrypt_secret()` al crear un bot.
  - `save_twitch()`: cifra `client_secret` con `encrypt_secret()` al guardar. Si el campo llega vacío (el cliente no tocó el campo de contraseña), conserva el secreto ya guardado en vez de borrarlo.
- **`templates/twitch.html`**: nueva sección "Credenciales de tu app de Twitch" con Client ID (texto) y Client Secret (contraseña, con placeholder "ya configurado" cuando ya hay uno guardado).
- **`requirements.txt`**: `cryptography==43.0.1` (ya estaba).
- **`migrate_encrypt_bot_tokens.py`**: sigue siendo válido para `bot_token`; los campos nuevos (como el de Twitch) no necesitan migración porque nunca existieron en texto plano.

### Cómo funciona

`Fernet` es cifrado simétrico (AES-128 + HMAC de integridad): la misma clave (`ENCRYPTION_KEY`) cifra y descifra. Un valor cifrado con la clave de un entorno **no se puede descifrar** con la clave de otro entorno -- por eso dev y producción deben tener claves distintas.

- Al **guardar** un campo sensible (crear un bot, guardar credenciales de Twitch, etc.), la ruta correspondiente lo cifra con `encrypt_secret()` antes de escribirlo en Mongo.
- Al **leer** la configuración (`get_config()`, que usan todas las rutas), `decrypt_sensitive_fields()` descifra automáticamente todo lo que esté en `SENSITIVE_CONFIG_PATHS`. Si un valor no está cifrado (documentos antiguos, o `ENCRYPTION_KEY` no configurada), se devuelve tal cual en vez de fallar.

### Pasos para activarlo

1. Genera una clave por entorno:
   ```
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. Configura `ENCRYPTION_KEY` con ese valor en las variables de entorno de Vercel de cada despliegue (una clave para dev, otra distinta para producción). **Guarda una copia fuera de Vercel** (gestor de contraseñas/secretos) -- si se pierde, los valores cifrados con ella no se pueden recuperar.
3. Vuelve a desplegar.
4. Ejecuta una vez `migrate_encrypt_bot_tokens.py` (con `MONGO_URI` y `ENCRYPTION_KEY` de ese entorno en tu shell) para cifrar los `bot_token` que ya existían en texto plano. Es seguro ejecutarlo más de una vez.
5. A partir de ahí, cualquier bot que crees desde `/admin` y cualquier credencial de Twitch que un cliente guarde quedan cifrados automáticamente.

### Cómo añadir un nuevo campo sensible en el futuro

1. Añade su ruta a `SENSITIVE_CONFIG_PATHS` (ej. `"youtube.credentials.api_key"`).
2. En la ruta Flask donde se guarda ese campo, cifra el valor con `encrypt_secret()` antes de pasarlo a `save_fields()` (sigue el mismo patrón "preservar si llega vacío" que `save_twitch()` si el campo es editable por el cliente).

No hace falta tocar `get_config()` de nuevo: `decrypt_sensitive_fields()` ya cubre cualquier ruta nueva del catálogo automáticamente.
