# encrypt_decrypt_cli_sql.py
import os, sys, getpass, hashlib, binascii
from cryptography.fernet import Fernet
from key_manager import generate_key, load_key
import db_manager
from datetime import datetime

# ---------- Password utils ----------
def hash_password(password, salt=None, iterations=200_000):
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return binascii.hexlify(pwd_hash).decode(), binascii.hexlify(salt).decode()

def verify_password(stored_hash_hex, stored_salt_hex, provided_password, iterations=200_000):
    salt = binascii.unhexlify(stored_salt_hex)
    test_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt, iterations)
    return binascii.hexlify(test_hash).decode() == stored_hash_hex

# ---------- Auth ----------
def register():
    username = input("Choose username: ").strip()
    if db_manager.get_user_by_username(username):
        print("User exists. Choose another username.")
        return None
    password = getpass.getpass("Choose password: ")
    password2 = getpass.getpass("Confirm password: ")
    if password != password2:
        print("Passwords don't match.")
        return None
    pwd_hash, salt = hash_password(password)
    uid = db_manager.create_user(username, pwd_hash, salt)
    print("User created with id", uid)
    return uid

def login():
    username = input("Username: ").strip()
    row = db_manager.get_user_by_username(username)
    if not row:
        print("No such user.")
        return None
    password = getpass.getpass("Password: ")
    if verify_password(row["password_hash"], row["salt"], password):
        print("Login successful.")
        return row["id"]
    else:
        print("Login failed.")
        return None

# ---------- Crypto helpers ----------
def get_cipher():
    key = load_key()
    return Fernet(key)

def encrypt_text_for_user(user_id):
    cipher = get_cipher()
    text = input("Enter text to encrypt: ").encode()
    enc = cipher.encrypt(text)
    print("Encrypted:", enc.decode())
    db_manager.add_log(user_id, "encrypt_text", target="text", detail="success")
    return enc

def decrypt_text_for_user(user_id):
    cipher = get_cipher()
    enc = input("Paste encrypted text: ").encode()
    try:
        dec = cipher.decrypt(enc).decode()
        print("Decrypted:", dec)
        db_manager.add_log(user_id, "decrypt_text", target="text", detail="success")
    except Exception as e:
        print("Decryption failed:", str(e))
        db_manager.add_log(user_id, "decrypt_text", target="text", detail=f"error: {e}")

def encrypt_file_for_user(user_id):
    cipher = get_cipher()
    path = input("File to encrypt: ").strip()
    if not os.path.exists(path):
        print("Not found.")
        return
    with open(path, "rb") as f:
        data = f.read()
    enc = cipher.encrypt(data)
    out = path + ".enc"
    with open(out, "wb") as f:
        f.write(enc)
    db_manager.add_file_record(user_id, os.path.basename(out), os.path.abspath(out), True)
    db_manager.add_log(user_id, "encrypt_file", target=os.path.basename(out), detail="success")
    print("Encrypted ->", out)

def decrypt_file_for_user(user_id):
    cipher = get_cipher()
    path = input("File to decrypt (.enc): ").strip()
    if not os.path.exists(path):
        print("Not found.")
        return
    with open(path, "rb") as f:
        enc = f.read()
    try:
        dec = cipher.decrypt(enc)
        out = path.replace(".enc", "_decrypted")
        with open(out, "wb") as f:
            f.write(dec)
        db_manager.add_file_record(user_id, os.path.basename(out), os.path.abspath(out), False)
        db_manager.add_log(user_id, "decrypt_file", target=os.path.basename(out), detail="success")
        print("Decrypted ->", out)
    except Exception as e:
        print("Failed:", e)
        db_manager.add_log(user_id, "decrypt_file", target=os.path.basename(path), detail=f"error: {e}")

def list_files(user_id):
    rows = db_manager.list_user_files(user_id)
    if not rows:
        print("No files recorded.")
        return
    print("Your files:")
    for r in rows:
        print(f" - {r['id']}: {r['filename']} (encrypted={bool(r['encrypted'])}) {r['created_at']}")

# ---------- Main ----------
def main():
    db_manager.init_db()
    if not os.path.exists("secret.key"):
        print("No key found. Generating one.")
        generate_key()

    print("1) Register  2) Login  3) Exit")
    choice = input("Enter: ").strip()
    if choice == "1":
        uid = register()
        if not uid:
            return
    elif choice == "2":
        uid = login()
        if not uid:
            return
    else:
        return

    while True:
        print("\n=== Menu ===")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. List My Files")
        print("6. Exit")
        c = input("Choice: ").strip()
        if c == "1":
            encrypt_text_for_user(uid)
        elif c == "2":
            decrypt_text_for_user(uid)
        elif c == "3":
            encrypt_file_for_user(uid)
        elif c == "4":
            decrypt_file_for_user(uid)
        elif c == "5":
            list_files(uid)
        elif c == "6":
            print("Bye.")
            break
        else:
            print("Invalid.")

if __name__ == "__main__":
    main()
