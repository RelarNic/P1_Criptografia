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
LENGTH = 32
N = 2**14
R = 8
P = 1

# Ruta al archivo JSON de la base de datos (usuarios y carteras)
DB_PATH = os.environ.get("DB_PATH", "users.json")

# Función para cargar la base de datos desde el JSON
# Esta función verifica si el archivo existe; si no, crea uno nuevo con estructura básica.
# Carga los usuarios y sus datos asociados, incluyendo carteras cifradas.
def load_db():
    if not os.path.exists(DB_PATH):
        db = {"users": {}, "meta": {"note": "Proyecto Criptografía UC3M - Gestión de Cartera de Activos"}}
        save_db(db)
        return db
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

# Función para guardar la base de datos en el JSON de forma segura
# Usa un archivo temporal para evitar corrupción durante la escritura.
def save_db(db):
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, DB_PATH)

# Función para iniciar sesión
# Solicita usuario y contraseña, verifica usando Scrypt para derivar y comparar la clave hashed.
# Si es exitoso, devuelve el username para usarlo en sesiones.
def login(db):
    print("=== Iniciar sesión ===")
    username = input("Usuario: ").strip()
    password = getpass.getpass("Contraseña: ")

    user = db.get("users", {}).get(username)
    
    if not user:
        print("Usuario no encontrado.\n")
        return None
    else: 
        salt = bytes.fromhex(user.get("salt", ""))
        key = user.get("password", "")
        if not scrypt_hash_verify(password, salt, key):
            print("Contraseña incorrecta.\n")
            return None
    
    print(f"Bienvenido/a, {username} (rol: {user.get('role','-')}).\n")
    return username

# Función para crear un nuevo usuario
# Solicita username, contraseña (verifica coincidencia), y rol.
# Genera salt aleatorio, hashea la contraseña con Scrypt y almacena en DB.
def create_user(db):
    print("=== Crear usuario ===")
    username = input("Nuevo usuario (username): ").strip()
    if not username:
        print("Nombre de usuario inválido.\n")
        return
    if username in db.get("users", {}):
        print("Ese usuario ya existe.\n")
        return
    pwd1 = getpass.getpass("Contraseña: ")
    pwd2 = getpass.getpass("Repite la contraseña: ")
    if pwd1 != pwd2:
        print("Las contraseñas no coinciden.\n")
        return
    role = input("Rol (inversor/admin): ").strip() or "inversor"
    if role not in ("inversor", "admin"):
        print("Rol inválido. Usando 'inversor' por defecto.")
        role = "inversor"
    
    salt = os.urandom(16)
    key_pwd = scrypt_hash_derive(pwd1, salt)

    db.setdefault("users", {})[username] = {
        "password": key_pwd,
        "salt": salt.hex(),
        "role": role,
        "portfolio": []  # Inicializa una cartera vacía (lista de activos, que se cifrarán al guardar)
    }
    save_db(db)
    print(f"Usuario '{username}' creado con rol '{role}'.\n")

# Función para derivar una clave hashed con Scrypt (para almacenamiento)
# Usa Scrypt como KDF (Key Derivation Function) para hacer el hashing lento y resistente a ataques de fuerza bruta.
def scrypt_hash_derive(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=LENGTH,
        n=N,
        r=R,
        p=P,
    )
    key = kdf.derive(password.encode())
    return key.hex()

# Función para verificar una contraseña contra un hash almacenado con Scrypt
# Re-deriva la clave y verifica si coincide, usando el método verify para evitar timing attacks.
def scrypt_hash_verify(password, salt, stored_key):
    kdf = Scrypt(
        salt=salt,
        length=LENGTH,
        n=N,
        r=R,
        p=P,
    )
    try:
        kdf.verify(password.encode(), bytes.fromhex(stored_key))
        return True
    except Exception:
        return False

# Función para cifrar datos de la cartera usando ChaCha20Poly1305 (cifrado autenticado simétrico)
# Genera una clave derivada de la contraseña del usuario con PBKDF2HMAC.
# Cifra la lista de activos (como JSON) con nonce aleatorio y AAD (datos autenticados adicionales).
def encrypt_portfolio(portfolio_data, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1200000,
    )
    key = kdf.derive(password.encode())
    
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    aad = b"portfolio data for user"
    data = json.dumps(portfolio_data).encode()
    ct = chacha.encrypt(nonce, data, aad)
    
    # Retorna el ciphertext, nonce y salt empaquetados en hex para almacenamiento
    return {
        "ciphertext": ct.hex(),
        "nonce": nonce.hex(),
        "salt": salt.hex()
    }

# Función para descifrar datos de la cartera usando ChaCha20Poly1305
# Usa la misma contraseña para derivar la clave, y verifica la integridad.
def decrypt_portfolio(encrypted_data, password):
    salt = bytes.fromhex(encrypted_data["salt"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1200000,
    )
    key = kdf.derive(password.encode())
    
    chacha = ChaCha20Poly1305(key)
    nonce = bytes.fromhex(encrypted_data["nonce"])
    ct = bytes.fromhex(encrypted_data["ciphertext"])
    aad = b"portfolio data for user"
    
    try:
        data = chacha.decrypt(nonce, ct, aad)
        return json.loads(data.decode())
    except Exception:
        print("Error al descifrar: integridad comprometida o contraseña incorrecta.")
        return None

# Función para agregar un activo a la cartera (solo para usuarios logueados)
# Solicita detalles del activo y lo añade a la lista de portfolio.
def add_asset(db, username):
    print("=== Agregar activo a la cartera ===")
    asset_name = input("Nombre del stock/cripto/ETF: ").strip()
    avg_price = input("Precio medio de compra: ").strip()
    positions = input("Número de posiciones: ").strip()
    
    user = db["users"][username]
    # Descifra la cartera actual si está cifrada
    if "encrypted_portfolio" in user:
        password = getpass.getpass("Contraseña para descifrar cartera: ")
        portfolio = decrypt_portfolio(user["encrypted_portfolio"], password)
        if portfolio is None:
            return
    else:
        portfolio = user.get("portfolio", [])
    
    asset = {
        "name": asset_name,
        "avg_price": avg_price,
        "positions": positions
    }
    portfolio.append(asset)
    
    # Cifra y guarda la cartera actualizada
    password = getpass.getpass("Contraseña para cifrar cartera: ")
    encrypted = encrypt_portfolio(portfolio, password)
    user["encrypted_portfolio"] = encrypted
    del user["portfolio"]  # Borra la versión plana por seguridad
    save_db(db)
    print("Activo agregado y cartera cifrada.\n")

# Función para mostrar la cartera (solo para usuarios logueados)
# Descifra y muestra los activos.
def show_portfolio(db, username):
    print("=== Mostrar cartera ===")
    user = db["users"][username]
    if "encrypted_portfolio" not in user:
        print("No hay cartera cifrada.\n")
        return
    
    password = getpass.getpass("Contraseña para descifrar: ")
    portfolio = decrypt_portfolio(user["encrypted_portfolio"], password)
    if portfolio is None:
        return
    
    if not portfolio:
        print("Cartera vacía.\n")
    else:
        print("Activos en la cartera:")
        for asset in portfolio:
            print(f" - {asset['name']}: Precio medio {asset['avg_price']}, Posiciones {asset['positions']}")
        print()

# Menú principal una vez logueado
# Ofrece opciones para gestionar la cartera.
def logged_in_menu(db, username):
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

# Función principal del programa
# Muestra el menú inicial y maneja las opciones.
def main():
    print("Bienvenido al Sistema de Gestión de Cartera de Activos")
    db = load_db()
    while True:
        print("Menú Principal:")
        print("1) Iniciar sesión")
        print("2) Crear usuario")
        print("3) Mostrar usuarios (solo nombres)")
        print("4) Salir")
        choice = input("> ").strip()
        if choice == "1":
            username = login(db)
            if username:
                logged_in_menu(db, username)
        elif choice == "2":
            create_user(db)
        elif choice == "3":
            users = list(db.get("users", {}).keys())
            if not users:
                print("(No hay usuarios todavía.)\n")
            else:
                print("Usuarios registrados:")
                for u in users:
                    print(" -", u)
                print()
        elif choice == "4":
            print("Hasta luego.")
            break
        else:
            print("Opción inválida.\n")

if __name__ == "__main__":
    main()