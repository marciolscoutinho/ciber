#!/usr/bin/env python3
"""
init_db.py — hack-me CTF
=========================
Initializes the SQLite database with users and hidden flag.
Run this once before starting the app.
"""

import os
import sqlite3

DB_PATH  = "hackme.db"
FLAG_DIR = os.path.join(os.path.dirname(__file__), "secret")
FLAG_2   = "FLAG{sql_1nj3ct10n_byp4ss3d_4uth3nt1c4t10n}"
FLAG_4   = "FLAG{p4th_tr4v3rs4l_3sc4p3d_th3_w3br00t}"


def init_database():
    """Create tables and seed data."""
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Users table — flag hidden in 'notes' column of admin user
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user',
            notes    TEXT DEFAULT ''
        )
    """)

    cur.executemany(
        "INSERT INTO users (username, password, role, notes) VALUES (?, ?, ?, ?)",
        [
            ("alice",  "password123",      "user",  ""),
            ("bob",    "hunter2",          "user",  ""),
            # Flag 2 is hidden here — only reachable via SQLi bypass
            ("admin",  "s3cr3t_4dm1n_pwd", "admin", FLAG_2),
        ],
    )

    # Products table (decoy — used in search route)
    cur.execute("DROP TABLE IF EXISTS products")
    cur.execute("""
        CREATE TABLE products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT,
            price REAL
        )
    """)

    cur.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [
            ("Firewall Pro",         499.99),
            ("VPN Gateway",          299.99),
            ("IDS Sensor",           149.99),
            ("Security Audit Suite", 999.99),
        ],
    )

    conn.commit()
    conn.close()
    print("[✓] Database initialized: hackme.db")


def init_files():
    """Create the files directory and flag file for path traversal."""
    # Web-accessible files
    files_dir = os.path.join(os.path.dirname(__file__), "files")
    os.makedirs(files_dir, exist_ok=True)

    with open(os.path.join(files_dir, "welcome.txt"), "w") as f:
        f.write("Welcome to HackMe Corp.\nThis portal is for internal use only.\n")

    with open(os.path.join(files_dir, "report.txt"), "w") as f:
        f.write("Q3 Security Report\n==================\nNo incidents recorded.\n")

    # Hidden flag — outside web root, reachable via path traversal
    os.makedirs(FLAG_DIR, exist_ok=True)

    with open(os.path.join(FLAG_DIR, "flag.txt"), "w") as f:
        f.write(f"{FLAG_4}\n")

    print("[✓] Files directory initialized")
    print("[✓] Secret directory initialized (contains FLAG 4)")


if __name__ == "__main__":
    init_database()
    init_files()
    print("\n[*] Setup complete. Run: python app.py")
