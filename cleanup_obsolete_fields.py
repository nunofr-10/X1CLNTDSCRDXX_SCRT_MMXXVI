"""
Script de limpieza de un solo uso: elimina de MongoDB los campos de los
módulos ya retirados del dashboard (Bienvenida y Estado/Descripción del
Bot), que el código ya no lee ni escribe pero que pueden seguir guardados
en documentos antiguos de la colección `config`.

Uso:
    1. Colócalo en el mismo entorno donde tengas configurada la variable de
       entorno MONGO_URI (la misma que usa app.py).
    2. Ejecuta:  python cleanup_obsolete_fields.py
    3. Revisa el resumen impreso (cuántos documentos se modificaron).
    4. Puedes borrar este archivo después de ejecutarlo -- no forma parte
       de la aplicación, es un script de mantenimiento puntual.

Este script NO toca "mensaje_bienvenida" (el mensaje de apertura del
módulo de Tickets) -- ese campo sigue activo y es independiente del
módulo de Bienvenida que se eliminó.
"""

import os

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.environ.get("MONGO_URI")
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "discord_bot")

# Campos obsoletos a eliminar de TODOS los documentos de la colección config.
OBSOLETE_FIELDS = ["welcome", "bot_identity"]


def main():
    if not MONGO_URI:
        print("[ERROR] La variable de entorno MONGO_URI no está configurada.")
        return

    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsAllowInvalidCertificates=True,
            serverSelectionTimeoutMS=5000,
        )
        db = client[MONGO_DB_NAME]
        config_collection = db["config"]

        # Cuenta cuántos documentos tienen todavía alguno de estos campos,
        # antes de tocarlos, para poder informar un resumen útil.
        query = {"$or": [{field: {"$exists": True}} for field in OBSOLETE_FIELDS]}
        affected_before = config_collection.count_documents(query)

        result = config_collection.update_many(
            {}, {"$unset": {field: "" for field in OBSOLETE_FIELDS}}
        )

        print(f"Documentos con campos obsoletos encontrados: {affected_before}")
        print(f"Documentos revisados: {result.matched_count}")
        print(f"Documentos modificados: {result.modified_count}")
        print("Campos eliminados en cada documento afectado:", ", ".join(OBSOLETE_FIELDS))
        print("Limpieza completada correctamente.")
    except PyMongoError as e:
        print(f"[ERROR] No se pudo completar la limpieza en MongoDB: {e}")


if __name__ == "__main__":
    main()
