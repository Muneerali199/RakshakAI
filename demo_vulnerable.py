import os
import sqlite3

def get_user(db: sqlite3.Connection, user_id: str):
    # SQL Injection - f-string in query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(cmd: str):
    # Command Injection
    os.system("ping " + cmd)

def store_token():
    # Hardcoded Secret
    api_key = "sk-abc123def456ghi789jkl"
    password = "admin123"
    return api_key, password

def render_page(name: str):
    # XSS vulnerability
    return f"<html><body>Hello {name}</body></html>"

def load_file(filename: str):
    # Path Traversal
    with open("/var/www/" + filename, "r") as f:
        return f.read()
