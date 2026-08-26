"""
Script de migración de un solo uso: cifra con Fernet cualquier "bot_token"
que todavía esté guardado en texto plano en la colección `config`, ahora
que app.py cifra los tokens nuevos automáticamente (ver encrypt_secret() /
decrypt_secret() en app.py).

Requisitos antes de ejecutarlo:
    1. Haber generado y configurado ENCRYPTION_KEY en el entorno donde
       corras este script (la MISMA clave que usa el despliegue de Flask
       de ese entorno -- dev o producción). Para generarla:

           python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

    2. Tener MONGO_URI (y MONGO_DB_NAME si lo usas) apuntando a la base de
       datos correcta.

Uso:
    python migrate_encrypt_bot_tokens.py

Es seguro ejecutarlo más de una vez: detecta qué tokens ya están cifrados
(intentando descifrarlos) y los deja tal cual, cifrando solo los que
todavía están en texto plano. Puedes borrar este archivo después de
ejecutarlo -- es un script de mantenimiento puntual, no forma parte de la
aplicación.
"""

import os

from pymongo import MongoClient
from pymongo.errors import PyMongoError
from cryptography.fernet import Fernet, InvalidToken

MONGO_URI = os.environ.get("MONGO_URI")
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "discord_bot")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


def main():
    if not MONGO_URI:
        print("[ERROR] La variable de entorno MONGO_URI no está configurada.")
        return
    if not ENCRYPTION_KEY:
        print("[ERROR] La variable de entorno ENCRYPTION_KEY no está configurada.")
        return

    try:
        fernet = Fernet(ENCRYPTION_KEY.encode())
    except (ValueError, TypeError) as e:
        print(f"[ERROR] ENCRYPTION_KEY no es una clave Fernet válida: {e}")
        return

    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsAllowInvalidCertificates=True,
            serverSelectionTimeoutMS=5000,
        )
        config_collection = client[MONGO_DB_NAME]["config"]

        docs = list(config_collection.find({"bot_token": {"$exists": True, "$ne": ""}}))

        already_encrypted = 0
        migrated = 0
        skipped_empty = 0

        for doc in docs:
            token = doc.get("bot_token", "")
            if not token:
                skipped_empty += 1
                continue

            try:
                fernet.decrypt(token.encode())
                already_encrypted += 1
                continue  # Ya estaba cifrado, no lo tocamos.
            except InvalidToken:
                pass  # Está en texto plano -- lo ciframos abajo.

            encrypted_token = fernet.encrypt(token.encode()).decode()
            config_collection.update_one(
                {"_id": doc["_id"]}, {"$set": {"bot_token": encrypted_token}}
            )
            migrated += 1

        print(f"Documentos con bot_token revisados: {len(docs)}")
        print(f"Ya estaban cifrados (sin cambios): {already_encrypted}")
        print(f"Cifrados en esta ejecución: {migrated}")
        print(f"Con bot_token vacío (omitidos): {skipped_empty}")
        print("Migración completada correctamente.")
    except PyMongoError as e:
        print(f"[ERROR] No se pudo completar la migración en MongoDB: {e}")


if __name__ == "__main__":
    main()
