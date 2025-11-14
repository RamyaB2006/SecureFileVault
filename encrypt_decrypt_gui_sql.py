# encrypt_decrypt_gui_sql.py
import tkinter as tk
from tkinter import messagebox, filedialog
import db_manager, key_manager
from cryptography.fernet import Fernet
import os, hashlib, binascii
from datetime import datetime

# PBKDF2 helpers (same as CLI)
def hash_password(password, salt=None, iterations=200_000):
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return binascii.hexlify(pwd_hash).decode(), binascii.hexlify(salt).decode()

def verify_password(stored_hash_hex, stored_salt_hex, provided_password, iterations=200_000):
    salt = binascii.unhexlify(stored_salt_hex)
    test_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt, iterations)
    return binascii.hexlify(test_hash).decode() == stored_hash_hex

# GUI app
class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Secure Data Protection (SQL)")
        self.root.geometry("720x520")
        db_manager.init_db()
        if not os.path.exists("secret.key"):
            key_manager.generate_key()
        self.user_id = None
        self.build_ui()

    def build_ui(self):
        # Auth frame
        frame_auth = tk.LabelFrame(self.root, text="Authentication")
        frame_auth.pack(fill="x", padx=10, pady=8)

        tk.Label(frame_auth, text="Username").grid(row=0, column=0)
        self.entry_user = tk.Entry(frame_auth)
        self.entry_user.grid(row=0, column=1)

        tk.Label(frame_auth, text="Password").grid(row=1, column=0)
        self.entry_pass = tk.Entry(frame_auth, show="*")
        self.entry_pass.grid(row=1, column=1)

        tk.Button(frame_auth, text="Register", command=self.register).grid(row=0, column=2, padx=6)
        tk.Button(frame_auth, text="Login", command=self.login).grid(row=1, column=2, padx=6)

        # Tools frame
        frame_tools = tk.LabelFrame(self.root, text="Tools")
        frame_tools.pack(fill="both", expand=True, padx=10, pady=8)

        tk.Label(frame_tools, text="Input / Encrypted Text").pack()
        self.txt_in = tk.Text(frame_tools, height=6)
        self.txt_in.pack(fill="x")

        tk.Label(frame_tools, text="Output").pack()
        self.txt_out = tk.Text(frame_tools, height=6)
        self.txt_out.pack(fill="x")

        btn_frame = tk.Frame(frame_tools)
        btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="Encrypt Text", command=self.encrypt_text).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Decrypt Text", command=self.decrypt_text).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Encrypt File", command=self.encrypt_file).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Decrypt File", command=self.decrypt_file).pack(side="left", padx=6)
        tk.Button(btn_frame, text="My Files", command=self.show_files).pack(side="left", padx=6)

    def register(self):
        username = self.entry_user.get().strip()
        pwd = self.entry_pass.get()
        if not username or not pwd:
            messagebox.showwarning("Input", "Provide username and password")
            return
        if db_manager.get_user_by_username(username):
            messagebox.showerror("Err", "User exists")
            return
        h, s = hash_password(pwd)
        uid = db_manager.create_user(username, h, s)
        messagebox.showinfo("OK", f"User created id={uid}")

    def login(self):
        row = db_manager.get_user_by_username(self.entry_user.get().strip())
        if not row:
            messagebox.showerror("Err", "No such user")
            return
        if verify_password(row["password_hash"], row["salt"], self.entry_pass.get()):
            self.user_id = row["id"]
            messagebox.showinfo("OK", f"Logged in as {self.entry_user.get().strip()}")
        else:
            messagebox.showerror("Err", "Wrong password")

    def get_cipher(self):
        key = key_manager.load_key()
        return Fernet(key)

    def encrypt_text(self):
        if not self.user_id:
            messagebox.showwarning("Auth", "Login first")
            return
        try:
            cipher = self.get_cipher()
            text = self.txt_in.get("1.0", tk.END).strip().encode()
            enc = cipher.encrypt(text)
            self.txt_out.delete("1.0", tk.END)
            self.txt_out.insert(tk.END, enc.decode())
            db_manager.add_log(self.user_id, "encrypt_text", target="text", detail="success")
        except Exception as e:
            messagebox.showerror("Err", str(e))
            db_manager.add_log(self.user_id, "encrypt_text", target="text", detail=f"error:{e}")

    def decrypt_text(self):
        if not self.user_id:
            messagebox.showwarning("Auth", "Login first")
            return
        try:
            cipher = self.get_cipher()
            enc = self.txt_in.get("1.0", tk.END).strip().encode()
            dec = cipher.decrypt(enc).decode()
            self.txt_out.delete("1.0", tk.END)
            self.txt_out.insert(tk.END, dec)
            db_manager.add_log(self.user_id, "decrypt_text", target="text", detail="success")
        except Exception as e:
            messagebox.showerror("Err", "Decryption failed")
            db_manager.add_log(self.user_id, "decrypt_text", target="text", detail=f"error:{e}")

    def encrypt_file(self):
        if not self.user_id:
            messagebox.showwarning("Auth", "Login first")
            return
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            enc = self.get_cipher().encrypt(data)
            out = path + ".enc"
            with open(out, "wb") as f:
                f.write(enc)
            db_manager.add_file_record(self.user_id, os.path.basename(out), os.path.abspath(out), True)
            db_manager.add_log(self.user_id, "encrypt_file", target=os.path.basename(out), detail="success")
            messagebox.showinfo("OK", f"Encrypted -> {out}")
        except Exception as e:
            messagebox.showerror("Err", str(e))
            db_manager.add_log(self.user_id, "encrypt_file", target=os.path.basename(path), detail=f"error:{e}")

    def decrypt_file(self):
        if not self.user_id:
            messagebox.showwarning("Auth", "Login first")
            return
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            with open(path, "rb") as f:
                enc = f.read()
            dec = self.get_cipher().decrypt(enc)
            out = path.replace(".enc", "_decrypted")
            with open(out, "wb") as f:
                f.write(dec)
            db_manager.add_file_record(self.user_id, os.path.basename(out), os.path.abspath(out), False)
            db_manager.add_log(self.user_id, "decrypt_file", target=os.path.basename(out), detail="success")
            messagebox.showinfo("OK", f"Decrypted -> {out}")
        except Exception as e:
            messagebox.showerror("Err", "Decryption failed")
            db_manager.add_log(self.user_id, "decrypt_file", target=os.path.basename(path), detail=f"error:{e}")

    def show_files(self):
        if not self.user_id:
            messagebox.showwarning("Auth", "Login first")
            return
        rows = db_manager.list_user_files(self.user_id)
        if not rows:
            messagebox.showinfo("Files", "No files recorded")
            return
        s = "\n".join([f"{r['id']}: {r['filename']} (enc={bool(r['encrypted'])}) - {r['created_at']}" for r in rows])
        messagebox.showinfo("My files", s)

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
