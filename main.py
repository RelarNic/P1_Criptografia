import json
import os
import getpass
import sys
import time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM


# Constantes para Scrypt (usadas en hashing de contraseñas)

#Ruta del archivo JSON de la base de datos (usuarios y carteras)
#environ toma en primer lugar la base de datos definida en variables de entorno, sino usa users.json por defecto
#Importante para seguridad, despliegue facil y colaboración
DB_PATH = os.environ.get("DB_PATH", "users.json")

#Función cargar base de datos o crearla si no existe
def load_db():
    if not os.path.exists(DB_PATH):
        db = {"users": {}, "meta": {"note": "Gestión de Cartera de Activos Cifrada UC3M- Por Nicolás Juliá y Miguel Alcaide"}}
        save_database(db)
        return db
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
    
#Función para guardar la base de datos de forma segura
def save_database(db):
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, DB_PATH)


