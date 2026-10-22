import os
import sqlite3

# 1. Hardcoded Secret / Credentials (ثغرة تسريب مفتاح/كلمة سر)
API_SECRET_KEY = "sk_live_99887766554433221100_SECRET"
DATABASE_PASSWORD = "AdminPassword123!"

# 2. Command Injection (ثغرة تنفيذ أوامر النظام)
def run_system_ping(user_input):
    # استخدام os.system مع مدخلات مباشرة من المستخدم
    os.system("ping -c 1 " + user_input)

# 3. SQL Injection (ثغرة استعلامات دمج الأوامر)
def get_user_data(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # استعلام SQL غير آمن ومدمج بنصوص مباشرة
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()