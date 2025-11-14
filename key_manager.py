# key_manager.py
from cryptography.fernet import Fernet
import os

KEY_PATH = "secret.key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    print("✔ AES Key generated and saved as", KEY_PATH)

def load_key():
    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError("Key file missing. Generate key first.")
    return open(KEY_PATH, "rb").read()
