# 🔐 SecureFileVault – AES-Based Web Encryption System
---

## 📌 Project Overview

**SecureFile Vault** is a secure web-based application designed to protect sensitive files using **AES-256 symmetric encryption** with **password-based key derivation**. Users can upload files, encrypt them securely, store metadata in a database, and later decrypt and download the files only with the correct password.  
The system ensures **confidentiality, integrity, and controlled access** to data.

---

## 🎯 Objectives

- 🔒 Secure user-uploaded files using **AES-256-GCM encryption**
- 🔑 Derive strong encryption keys from user passwords using **PBKDF2**
- 🗄️ Store encrypted file metadata safely in a **SQLite database**
- 🌐 Provide a simple and intuitive **web-based interface**
- 🛡️ Prevent unauthorized access and tampering of files

---

## 🏗️ System Architecture

1. **Web Interface (Client Layer)**  
   - HTML + CSS with Jinja2 templates  
   - Allows users to:
     - Upload files  
     - Enter encryption/decryption passwords  
     - Download decrypted files  

2. **Backend Server (Application Layer)**  
   - **Flask (Python)** web framework  
   - Handles:
     - File uploads  
     - Encryption & decryption logic  
     - Database interactions  
     - Secure file downloads  

3. **Cryptography Engine (Security Layer)**  
   - **AES-256-GCM** for authenticated encryption  
   - **PBKDF2-HMAC-SHA256** for password-based key derivation  
   - Random **salt** and **nonce** generated per file  

4. **Database Layer**  
   - **SQLite** database  
   - Stores:
     - Encrypted file metadata  
     - Salt, nonce, KDF iterations  
     - File size and timestamps  

---

## 🔐 Encryption & Security Approach

- **Algorithm Used**: AES-256-GCM  
- **Key Derivation**: PBKDF2 with SHA-256  
- **Key Size**: 256 bits  
- **Salt**: Random 16 bytes (per file)  
- **Nonce**: Random 12 bytes (per file)  
- **Authentication**: Built-in integrity check using GCM mode  

🔹 If the wrong password is used, decryption **fails safely** without revealing any data.  
🔹 Passwords are **never stored** in the database or server.

---

## ⚙️ Tools & Technologies

- **Backend**: Python, Flask  
- **Cryptography**: `cryptography` library (AES-GCM, PBKDF2)  
- **Database**: SQLite  
- **Frontend**: HTML, CSS, Jinja2  
- **Version Control**: Git  
- **Repository Hosting**: GitHub  
- **Development Environment**: VS Code  

---

## 📊 Key Features

- 📁 Secure file upload & encryption  
- 🔓 Password-protected decryption & download  
- 🗃️ Encrypted file metadata storage  
- 🧾 File listing dashboard  
- ⚠️ Error handling for invalid passwords  
- 🖥️ Lightweight and runs locally without cloud dependency  

---

## 🧪 Example Workflow

1. User uploads a file via the web interface  
2. User enters a password  
3. File is encrypted using AES-256-GCM  
4. Encrypted file is stored on disk  
5. Metadata (salt, nonce, iterations) stored in SQLite  
6. User selects a file and enters password to decrypt  
7. Decrypted file is downloaded securely  

---

## 📂 Database Schema (Simplified)

| Field Name        | Description                          |
|------------------|--------------------------------------|
| id               | Unique file ID                       |
| original_name    | Original file name                   |
| enc_filename     | Encrypted file name                  |
| salt             | Random salt (BLOB)                   |
| nonce            | AES-GCM nonce (BLOB)                 |
| kdf_iterations   | PBKDF2 iteration count               |
| size             | Encrypted file size                  |
| created_at       | Timestamp                            |

---

## 🚀 Advantages

- ✅ Strong encryption with industry standards  
- ✅ Web-based and user-friendly  
- ✅ No password storage → improved security  
- ✅ Lightweight & easy to deploy  
- ✅ Suitable for academic and demo purposes  

---

## 🔭 Future Scope

- 👤 User authentication and role-based access  
- ☁️ Cloud storage integration (AWS S3 / Firebase)  
- 🔐 Support for Argon2 key derivation  
- 📱 Responsive UI and improved frontend design  
- 📜 Audit logging and activity tracking  

---

## 🚧 Current Status

- ✔ Core encryption and decryption implemented  
- ✔ SQLite database integration completed  
- ✔ Web interface functional  
- ✔ GitHub version control enabled  
- 🔄 Future enhancements planned  

---

## 🧾 Disclaimer

⚠️ This project is intended for **educational and demonstration purposes**.  
For production environments, additional security hardening, HTTPS, authentication, and secure deployment practices are required.

---
