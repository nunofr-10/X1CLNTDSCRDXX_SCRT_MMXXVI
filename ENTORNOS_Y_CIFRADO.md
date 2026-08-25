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

## 2. Cifrado de datos sensibles

### Qué se cifra ahora mismo

El único dato sensible que el dashboard guarda hoy en MongoDB es **`bot_token`**: el token del bot de Discord de cada cliente (se guarda al crear un bot desde `/admin`). Con acceso a ese token en texto plano, cualquiera con acceso a la base de datos tendría control total sobre el bot de Discord de ese cliente -- por eso es el campo prioritario.

Actualmente Twitch solo guarda el nombre/URL del canal (dato público), no credenciales, así que no hay nada que cifrar ahí todavía. Si en el futuro añades autenticación con la API de Twitch (Client ID/Secret, tokens OAuth), sigue el mismo patrón descrito abajo.

### Archivos que se tocaron

- **`app.py`**:
  - Import `from cryptography.fernet import Fernet, InvalidToken`.
  - Nuevas variables `ENCRYPTION_KEY`, `_fernet`.
  - Nuevas funciones `encrypt_secret(value)` / `decrypt_secret(value)`.
  - `admin_create_bot()`: cifra `bot_token` con `encrypt_secret()` antes de guardarlo.
  - `get_config()`: descifra `merged["bot_token"]` con `decrypt_secret()` justo antes de devolver la configuración -- así el resto del código (`active_bot_token()`, llamadas a la API de Discord, etc.) sigue recibiendo el token en texto plano sin que tengas que tocar nada más.
- **`requirements.txt`**: se añadió `cryptography==43.0.1`.
- **`migrate_encrypt_bot_tokens.py`** (nuevo, en la raíz): script de un solo uso para cifrar los `bot_token` que ya existían en texto plano antes de este cambio.

### Cómo funciona

`Fernet` es cifrado simétrico (AES-128 + HMAC de integridad): la misma clave (`ENCRYPTION_KEY`) cifra y descifra. Un valor cifrado con la clave de un entorno **no se puede descifrar** con la clave de otro entorno -- por eso dev y producción deben tener claves distintas.

- Al **guardar** un bot nuevo (`admin_create_bot`), el token se cifra antes de escribirlo en Mongo.
- Al **leer** la configuración (`get_config()`, que usan todas las rutas), el token se descifra automáticamente. Si el valor guardado no está cifrado (documentos antiguos, o `ENCRYPTION_KEY` no configurada), se devuelve tal cual en vez de fallar -- así no se rompe nada mientras migras.

### Pasos para activarlo

1. Genera una clave por entorno:
   ```
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. Configura `ENCRYPTION_KEY` con ese valor en las variables de entorno de Vercel de cada despliegue (una clave para dev, otra distinta para producción). **Guarda una copia fuera de Vercel** (gestor de contraseñas/secretos) -- si se pierde, los tokens cifrados con ella no se pueden recuperar.
3. Vuelve a desplegar.
4. Ejecuta una vez `migrate_encrypt_bot_tokens.py` (con `MONGO_URI` y `ENCRYPTION_KEY` de ese entorno en tu shell) para cifrar los `bot_token` que ya existían en texto plano. Es seguro ejecutarlo más de una vez.
5. A partir de ahí, cualquier bot que crees desde `/admin` queda cifrado automáticamente.

### Cómo extender el cifrado a nuevos campos sensibles

Cuando añadas un campo sensible nuevo (por ejemplo, credenciales de Twitch):

1. Al guardarlo: `campo_cifrado = encrypt_secret(valor_del_formulario)`.
2. Al leerlo dentro de `get_config()`, junto al resto del merge: `merged["ese_campo"] = decrypt_secret(merged.get("ese_campo", ""))`.

Con eso, el resto del código sigue trabajando con el valor en texto plano sin cambios adicionales.
