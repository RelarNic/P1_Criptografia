import json
import os
import getpass
import sys
import time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM


# Constantes para PBKDF2 (usadas en hashing de contraseñas)

L=32  # Longitud de la clave derivada en bytes
i=1_200_000  # Número de iteraciones para PBKDF2

#Ruta del archivo JSON de la base de datos (usuarios y carteras)
#environ toma en primer lugar la base de datos definida en variables de entorno, sino usa users.json por defecto
#Importante para seguridad, despliegue facil y colaboración
DB_PATH = os.environ.get("DB_PATH", "users.json")

#Función cargar base de datos o crearla si no existe
def load_db():
    #Si no existe el archivo, crea uno nuevo con estructura básica
    if not os.path.exists(DB_PATH):
        db = {"users": {}, "meta": {"note": "Gestión de Cartera de Activos Cifrada UC3M- Por Nicolás Juliá y Miguel Alcaide"}}
        save_database(db)
        return db
    #Si existe, carga los usuarios y sus datos asociados
    #utilizando 'with' para asegurar el cierre del archivo, evita leaks
    #PREGUNTAR SI SE PUEDE USAR WITH O HAY QUE USAR FORMA MANUAL
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
    
#Función para guardar la base de datos de forma segura
def save_database(db):
    #Usa un archivo temporal para evitar corrupcion durante la escritura
    tmp = DB_PATH + ".tmp"
    #"w" es para escritura, si no existe crea el archivo
    with open(tmp, "w", encoding="utf-8") as f:
        #Dump escribe el JSON en el archivo con formato legible
        #Se toma la base de datos y se escribe en el archivo temporal
        #Mas adelante, el archivo temporal reemplaza al original solo si todo ha ido bien
        json.dump(db, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, DB_PATH)

def create_user(db):
    print("=== Registrar nuevo usuario ===")
    username = input("Nuevo usuario: ").strip()
    if not username:
        print("El nombre de usuario no puede estar vacío.\n")
        return
    #get metodo de diccionario
    if username in db.get("users", {}):
        print("El usuario ya existe.\n")
        return
    #con getpass no se muestra la contraseña en pantalla
    password = getpass.getpass("Contraseña: ")
    password_confirm = getpass.getpass("Confirmar contraseña: ")
    if password != password_confirm:
        print("Las contraseñas no coinciden.\n")
        return
    #Ahora creacion de salt, hash y guardado en db
    #El salt permite que el mismo password genere hashes diferentes
    salt = os.urandom(16)  # Genera un salt aleatorio de 16 bytes
    #PBKDF2HMAC es una función de derivación de claves que aplica 
    #repetidamente una función hash (SHA256) para hacer más difícil ataques de fuerza bruta
    #Se prefiere a scrypt porque menos consumo de memoria y CPU
    #aunque scrypt es más seguro contra ataques de hardware especializado
    #despues se usará chacha20poly1305 para cifrar las carteras
    key_pswd = passwd_hash_derive(password, salt)
    #Almacenamiento en la base de datos
    # Asegura que existe la sección de usuarios
    #guardamos el salt porque es necesario para verificar la contraseña luego
    db.setdefault("users", {})[username] = {
        "password": key_pswd,
        "salt": salt.hex(),
        "portfolio": [],
    }
    save_database(db)
    print(f"Usuario '{username}' creado con éxito.\n")


def passwd_hash_derive(password: str, salt: bytes) -> str:
    """Deriva una clave segura a partir de la contraseña y el salt usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=L,
        salt=salt,
        iterations=i,
    )
    key = kdf.derive(password.encode())
    return key.hex()


def login_user(db):
    print("=== Iniciar sesión ===")
    user = input("Usuario: ").strip()
    password = getpass.getpass("Contraseña: ")

    


# Código principal para probar las funciones
if __name__ == "__main__": 
#if name se usa para que al importar este archivo en otro no se ejecute este bloque,
#solo las funciones requeridas
    print("Bienvenido al sistema de gestión de carteras cifradas UC3M.")
    #para comprobar funciones, luego se quitan 
    print("Cargando/creando base de datos...")
    db = load_db()
    print(f"Base de datos cargada: {db}")
    print(f"Archivo creado en: {DB_PATH}")
    funcionando = True
    while funcionando:
        print("Menú inicial")
        print("1. Iniciar sesión")
        print("2. Registrar nuevo usuario")
        print("3. Mostrar usuarios (solo nombres)") 
        print("4. Salir")
        eleccion = input("Seleccione una opción: ").strip()
        if eleccion == "1":
            if login_user(db):
                logged_menu(db)
            else:
                print("Error en el inicio de sesión.\n")
        elif eleccion == "2":
            create_user(db)
        