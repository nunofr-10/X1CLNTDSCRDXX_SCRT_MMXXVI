# Logs de sanciones de Twitch en tiempo real (EventSub)

Guía de configuración del nuevo módulo de logs de sanciones de Twitch (bans, timeouts,
advertencias y mensajes borrados) para la plataforma multi-cliente. Cada cliente vincula
**su propia** cuenta de Twitch y su propia app de Twitch Developer; la plataforma nunca
comparte credenciales ni tokens entre clientes.

## 1. Cómo funciona (resumen técnico)

1. Cada cliente ya tiene un **Client ID / Client Secret** de su propia app de Twitch
   (pantalla `/twitch`, sección "Credenciales de tu app de Twitch" — esto ya existía).
2. El cliente pulsa **"Vincular mi cuenta de Twitch"**: autoriza en Twitch los scopes de
   moderación necesarios (`/twitch/oauth/login` → `/twitch/oauth/callback`).
3. Al volver del OAuth, la plataforma:
   - Guarda `broadcaster_id`, `access_token` y `refresh_token` (los dos tokens, cifrados
     con Fernet) en el documento Mongo de ese cliente.
   - Crea automáticamente 3 suscripciones EventSub en Twitch (`channel.ban`,
     `channel.warning.send`, `channel.chat.message_delete`) usando un **App Access
     Token** (client credentials del propio cliente) — Twitch exige este tipo de token
     para las suscripciones de transporte "webhook", nunca el token de usuario.
4. Twitch envía cada sanción real a **una única URL fija** de la plataforma
   (`/webhooks/twitch/eventsub`), compartida por todos los clientes. La plataforma:
   - Verifica la firma HMAC-SHA256 del webhook (rechaza cualquier request que no venga
     de Twitch).
   - Busca en MongoDB qué cliente es dueño de ese `broadcaster_id` (aislamiento total:
     nunca se mezclan sanciones de un canal con las de otro).
   - Comprueba los filtros que ese cliente configuró (`ban` / `timeout` / `warning` /
     `delete_message`).
   - Si el filtro está activado, envía el aviso al `log_channel_id` de Discord de ESE
     cliente, usando el `bot_token` de ESE cliente.

## 2. Variables de entorno nuevas (una sola vez, a nivel de plataforma)

Añádelas donde ya tienes `MONGO_URI`, `ENCRYPTION_KEY`, etc. (Vercel → Settings →
Environment Variables, o tu `.env` local):

| Variable | Qué es | Ejemplo |
|---|---|---|
| `TWITCH_OAUTH_REDIRECT_URI` | URL de callback de la vinculación OAuth | `https://tu-dashboard.com/twitch/oauth/callback` |
| `TWITCH_EVENTSUB_CALLBACK_URL` | URL pública donde Twitch envía las sanciones | `https://tu-dashboard.com/webhooks/twitch/eventsub` |
| `TWITCH_EVENTSUB_SECRET` | Secreto para firmar/verificar los webhooks (HMAC) | genera uno con `openssl rand -hex 32` |

Notas:
- Las tres deben usar **HTTPS** en producción (Twitch no admite `http://` salvo en
  pruebas locales con `localhost`).
- `TWITCH_EVENTSUB_SECRET` es **compartido entre todos los clientes** — no pasa nada,
  porque cada evento ya se identifica y aísla por `broadcaster_id`, no por el secreto.
  No lo publiques ni lo subas al repositorio.
- Si más adelante separas dominio de pruebas y dominio de clientes (como ya hicimos con
  `APP_ENV`), estas 3 variables valen la URL del dominio de **producción** en ese
  entorno, y la de pruebas en el de desarrollo.

## 3. Qué debe hacer CADA cliente en la Twitch Developer Console

Esto lo hace el cliente (o tú, si le ayudas), una vez por cada app de Twitch:

1. Entra en la [Twitch Developer Console](https://dev.twitch.tv/console/apps) y crea una
   app (o usa la que ya tenga para el Client ID/Secret que puso en `/twitch`).
2. En **"OAuth Redirect URLs"**, añade exactamente el valor de
   `TWITCH_OAUTH_REDIRECT_URI` (el mismo para todos los clientes, es la URL de la
   plataforma, no la suya personal).
3. Categoría de la app: cualquiera que permita scopes de moderador está bien (p. ej.
   "Chat Bot" o "Application Integration").
4. Copia el **Client ID** y genera/copia el **Client Secret** → pégalos en el dashboard,
   en `/twitch`, sección "Credenciales de tu app de Twitch" → Guardar.
5. Vuelve a `/twitch`, baja hasta **"Vincular cuenta de Twitch"** y pulsa **"Vincular mi
   cuenta de Twitch"**.
6. Inicia sesión con la cuenta de streamer (el broadcaster del canal que quiere
   monitorizar) y acepta los permisos que pide la pantalla de Twitch. Los scopes
   solicitados son:
   - `channel:moderate` → necesario para recibir baneos y timeouts.
   - `moderator:manage:warnings` → necesario para recibir advertencias.
   - `user:read:chat` y `channel:bot` → necesarios para recibir mensajes borrados.
7. Si todo va bien, verá un aviso verde de "Cuenta de Twitch vinculada y logs de
   sanciones activados" y el ID de su canal.
8. Por último, elige el **canal de Discord** para los avisos y activa/desactiva los
   tipos de sanción que quiera recibir (checkboxes de Baneos / Timeouts / Advertencias /
   Mensajes borrados) → Guardar cambios.

No hace falta tocar nada más: a partir de ahí, cualquier sanción real en su canal de
Twitch llega a Discord automáticamente, en segundos.

## 4. Volver a vincular / renovar permisos

Si el cliente cambia su Client ID/Secret de Twitch, o Twitch revoca la autorización, el
botón cambia a **"Volver a vincular / renovar permisos"** — es seguro pulsarlo tantas
veces como haga falta: si las suscripciones EventSub ya existían, Twitch simplemente
confirma que siguen activas (no se duplican avisos).

## 5. Solución de problemas

- **"Cuenta de Twitch vinculada, pero no se pudieron activar los avisos"**: normalmente
  falta algún scope. Revisa el mensaje de error concreto que muestra el dashboard (se
  lista tipo por tipo: `channel.ban`, `channel.warning.send`,
  `channel.chat.message_delete`) y verifica los scopes en el paso 6.
- **No llega ningún aviso aunque la vinculación fue exitosa**: comprueba que
  `TWITCH_EVENTSUB_CALLBACK_URL` sea accesible públicamente por HTTPS (Twitch la
  verifica con un "challenge" al crear cada suscripción; si el servidor no está
  desplegado o la URL apunta a `localhost`, la suscripción no llegará a activarse en
  producción).
- **Error de firma / 403 en el webhook**: `TWITCH_EVENTSUB_SECRET` no coincide entre lo
  que se usó al crear las suscripciones y lo que tiene configurado el servidor ahora —
  si cambias esta variable, los clientes deben volver a vincular su cuenta.
- La API de sanciones de Twitch (especialmente `channel.chat.message_delete` y sus
  scopes) ha cambiado más de una vez en los últimos años. Si algún tipo de sanción deja
  de dispararse, conviene revisar la
  [referencia oficial de tipos de suscripción de EventSub](https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/)
  por si Twitch actualizó el scope o la versión requerida.
