# db_manager.py
import sqlite3
import os
from datetime import datetime

DB_PATH = "aes_secure_data.db"

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True) if os.path.dirname(DB_PATH) else None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    if not os.path.exists(DB_PATH):
        conn = get_conn()
        cur = conn.cursor()
        with open("init_db.sql", "r", encoding="utf-8") as f:
            cur.executescript(f.read())
        conn.commit()
        conn.close()
        print("Initialized DB:", DB_PATH)
    else:
        # still ensure tables exist (safe)
        conn = get_conn()
        cur = conn.cursor()
        with open("init_db.sql", "r", encoding="utf-8") as f:
            cur.executescript(f.read())
        conn.commit()
        conn.close()

# ---------- Users ----------
def create_user(username, password_hash, salt):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
        (username, password_hash, salt, datetime.utcnow().isoformat())
    )
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid

def get_user_by_username(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

# ---------- Files ----------
def add_file_record(user_id, filename, filepath, encrypted):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO files (user_id, filename, filepath, encrypted, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, filename, filepath, int(bool(encrypted)), datetime.utcnow().isoformat())
    )
    conn.commit()
    fid = cur.lastrowid
    conn.close()
    return fid

def list_user_files(user_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

# ---------- Audit Logs ----------
def add_log(user_id, action, target=None, detail=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs (user_id, action, target, detail, timestamp) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, target, detail, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
