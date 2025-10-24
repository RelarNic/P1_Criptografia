import json
import os
import getpass
import sys
import time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM



#A CAMBIAR + GRANULAR



# Constantes para PBKDF2 y scrypt (usadas en hashing de contraseñas)

L=32  # Longitud de la clave derivada en bytes
I=1200000  # Número de iteraciones para PBKDF2
P=1  # Parámetro de paralelismo para Scrypt
N=2**14  # Factor de costo para Scrypt
R=8  # Bloque de tamaño para Scrypt



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
    portfolio_salt = os.urandom(16) #un salt para cada vez que se cifre un activo
    #scrypt es una función de derivación de claves que aplica 
    #repetidamente una función hash para hacer más difícil ataques de fuerza bruta
    # scrypt es más seguro contra ataques de hardware especializado
    #despues se usará chacha20poly1305 para cifrar las carteras
    key_pswd = passwd_hash_derive(password, salt)
    #Almacenamiento en la base de datos
    # Asegura que existe la sección de usuarios
    #guardamos el salt porque es necesario para verificar la contraseña luego
    db.setdefault("users", {})[username] = {
        "password": key_pswd,
        "salt": salt.hex(),
        "portfolio_salt": portfolio_salt.hex(),
        "portfolio": {},
    }
    save_database(db)
    print(f"Usuario '{username}' creado con éxito.\n")
    
def derive_portfolio_key(password: str, portfolio_salt: bytes) -> bytes:
	"""Deriva clave para cifrar/descifrar todo el portfolio"""
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=portfolio_salt,
		iterations=1_200_000
	)
	return kdf.derive(password.encode())

#Ultima parte del projecto, cifrar carteras
def encrypt_asset(password, portfolio_salt: bytes, asset: dict) -> dict:
    key = derive_portfolio_key(password, portfolio_salt)
    #Empieza generando una clave con PDFK2HMAC (derivada de la contraseña) que luego usa ChaCha20Poly1305
    chacha = ChaCha20Poly1305(key)
    #chacha es un valor aleatorio que debe ser único para cada cifrado con la misma clave
    nonce = os.urandom(12)  # Nonce de 12 bytes para ChaCha20Poly1305
    #nonce no se repite nunca con la misma clave
    aad = b"portfolio data for user"  # Datos autenticados adicionales, verifican integridad pero no se cifran
    data = json.dumps(asset).encode()  # Convierte el activo a JSON y luego a bytes
    ct = chacha.encrypt(nonce, data, aad)  # Cifra los datos con ChaCha20Poly1305

    return {
        "ciphertext": ct.hex(),
        "nonce": nonce.hex(),
    }

def decrypt_asset(enc_data, password, portfolio_salt):
    key = derive_portfolio_key(password, portfolio_salt)
    #importante no reusar el salt para esto -> HECHO
    chacha = ChaCha20Poly1305(key)
    nonce = bytes.fromhex(enc_data["nonce"])
    ct = bytes.fromhex(enc_data["ciphertext"])
    aad = b"portfolio data for user"    
    try:
        data = chacha.decrypt(nonce, ct, aad)
        plaintext = json.loads(data.decode())
        return plaintext
    except Exception:
        print("Error al descifrar la cartera")
        return None

def passwd_hash_derive(password: str, salt: bytes) -> str:
    """Deriva una clave segura a partir de la contraseña y el salt usando Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=L,
        n=N,
        r=R,
        p=P,
    )
    key = kdf.derive(password.encode())
    return key.hex()


def login_user(db):
    print("=== Iniciar sesión ===")
    user = input("Usuario: ").strip()
    password = getpass.getpass("Contraseña: ")
    user_check = db.get("users", {}).get(user)
    if not user_check:
        print("Usuario no encontrado.\n")
        return 
    else:
        salt = bytes.fromhex(user_check.get("salt", ""))
        key = user_check.get("password", "")
        if not passwd_hash_verify(password, salt, key):
            print("Contraseña incorrecta.\n")
            return 
    print(f"Bienvenido/a, {user}.\n")
    return user

def passwd_hash_verify(password: str, salt: bytes, key_hex: str) -> bool:
	"""Verifica que la contraseña proporcionada coincide con el hash almacenado."""
	kdf = Scrypt(
        salt=salt,
        length=L,
        n=N,
        r=R,
        p=P,
    )
	try:
		kdf.verify(password.encode(), bytes.fromhex(key_hex))
		return True
	except Exception:
		return False


def logged_menu(db, username):
    while True:
        print("Menú de Cartera:")
        print("1) Agregar activo")
        print("2) Mostrar cartera")
        print("3) Cerrar sesión")
        choice = input("> ").strip()
        if choice == "1":
            add_asset(db, username)
        elif choice == "2":
            show_portfolio(db, username)
        elif choice == "3":
            print("Sesión cerrada.\n")
            break
        else:
            print("Opción inválida.\n")
            
def add_asset(db, username):
    print("=== Agregar activo ===")
    activo = input("Nombre del activo: ").strip()
    price = input("Precio medio de compra: ").strip()
    quantity = input("Cantidad: ").strip()
    if not activo or not price or not quantity:
        print("Todos los campos son obligatorios.\n")
        return
    
    password = getpass.getpass("Contraseña: ")
    user = db["users"][username]  # Referencia directa al usuario
    
    # Obtener el portfolio_salt del usuario
    portfolio_salt = bytes.fromhex(user["portfolio_salt"])
    
    # Crear datos del activo
    asset_data = {
        "precio": float(price),
        "cantidad": float(quantity)
    }
    
    # Cifrar el activo individualmente
    encrypted_asset = encrypt_asset(password, portfolio_salt, asset_data)
    
    # Guardar activo cifrado en el portfolio
    user.setdefault("portfolio", {})[activo] = encrypted_asset
    
    save_database(db)
    print(f"Activo '{activo}' agregado y cifrado.\n")
    
def show_portfolio(db, username):
    print(f"=== Cartera de {username} ===")
    user = db["users"][username]
    
    # Verificar si hay portfolio con activos
    portfolio = user.get("portfolio", {})
    if not portfolio:
        print("La cartera está vacía.\n")
        return
    
    password = getpass.getpass("Contraseña para descifrar: ")
    portfolio_salt = bytes.fromhex(user["portfolio_salt"])
    
    print("Activos en la cartera:")
    for activo, encrypted_asset in portfolio.items():
        try:
            # Descifrar cada activo individualmente
            asset_data = decrypt_asset(encrypted_asset, password, portfolio_salt)
            if asset_data:
                print(f" - {activo}: Precio medio ${asset_data['precio']}, Cantidad {asset_data['cantidad']}")
            else:
                print(f" - {activo}: Error al descifrar")
        except Exception as e:
            print(f" - {activo}: Error al descifrar - {e}")
    print()  # Línea en blanco al final




# Código principal para probar las funciones
if __name__ == "__main__": 
#if name se usa para que al importar este archivo en otro no se ejecute este bloque,
#solo las funciones requeridas
    print("Bienvenido al sistema de gestión de carteras cifradas UC3M.")
    #para comprobar funciones, luego se quitan 
    print("Cargando/creando base de datos...")
    db = load_db()
    print(f"Base de datos cargada")
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
            username = login_user(db)
            if username:
                logged_menu(db, username)
            else:
                print("Error en el inicio de sesión.\n")
        elif eleccion == "2":
            create_user(db)
        elif eleccion == "3":
            j = 1
            for username in db.get("users", {}):
                print(str(j) + " - " + username)
                j += 1
        elif eleccion == "4":
            print("Saliendo del programa. ¡Hasta luego!")
            funcionando = False
