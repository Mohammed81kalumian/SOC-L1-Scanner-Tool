import os
import subprocess
import sqlite3

# 1. Hardcoded Plaintext Credentials & Secrets (Security Hotspot)
API_SECRET_KEY = "sk_live_998877665544332211"
ADMIN_PASSWORD = "Password12345!"

# 2. Command Injection (Vulnerability)
def run_user_cmd(user_input):
    # Executing raw command with shell=True
    subprocess.call("ping -c 1 " + user_input, shell=True)

# 3. SQL Injection (Vulnerability)
def get_user_data(user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Unsanitized string concatenation into SQL query
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

# 4. Weak Hashing / Insecure Cryptography
import hashlib
def hash_pass(password):
    # Using insecure MD5 hashing
    return hashlib.md5(password.encode()).hexdigest()
