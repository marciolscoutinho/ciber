#!/usr/bin/env python3
"""
test_vulnerable_app.py
===============================================================================
Author    : Márcio Coutinho (Cibersecurity Specialist       
Date      : 31/07/2025
===============================================================================
WARNING: This file contains INTENTIONAL vulnerabilities for testing and
         demonstrating VulnHunter. DO NOT use it in production.
"""

import os
import re
import sys
import pickle
import random
import hashlib
import sqlite3
import subprocess
import yaml

# ──────────────────────────────────────────────────────────────
# VH-060 | CWE-259 | Hardcoded Credential
# ──────────────────────────────────────────────────────────────
DB_HOST     = "localhost"
DB_USER     = "admin"
password    = "SuperSecret123!"      # <-- hardcoded password
secret_key  = "my-flask-secret-key" # <-- hardcoded secret

# ──────────────────────────────────────────────────────────────
# VH-062 | CWE-798 | Exposed AWS Access Key
# ──────────────────────────────────────────────────────────────
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_user(username: str) -> dict:
    """
    VH-001 | CWE-89 | SQL Injection via f-string
    The query is constructed with an f-string, allowing SQL injection.
    Example payload: username = "' OR '1'='1"
    """
    conn   = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query  = f"SELECT * FROM users WHERE username = '{username}'"  # VULN
    cursor.execute(query)
    return cursor.fetchone()


def authenticate(user: str, pwd: str) -> bool:
    """
    VH-002 | CWE-89 | SQL Injection via Concatenation
    """
    conn   = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query  = "SELECT * FROM users WHERE user='" + user + "' AND pass='" + pwd + "'"  # VULN
    result = cursor.execute(query).fetchone()
    return result is not None


def run_ping(host: str) -> str:
    """
    VH-010 | CWE-78 | OS Command Injection via os.system
    Example payload: host = "google.com; rm -rf /"
    """
    os.system(f"ping -c 4 {host}")   # VULN


def list_files(directory: str) -> None:
    """
    VH-011 | CWE-78 | Command Injection via subprocess shell=True
    """
    result = subprocess.run(f"ls -la {directory}", shell=True, capture_output=True)  # VULN
    print(result.stdout.decode())


def calculate_expression(expr: str) -> any:
    """
    VH-012 | CWE-94 | Code Injection via eval()
    Example payload: expr = "__import__('os').system('whoami')"
    """
    return eval(expr)   # VULN


def hash_password_md5(password: str) -> str:
    """
    VH-030 | CWE-327 | Weak MD5 Algorithm
    MD5 has been cryptographically broken since 2004.
    """
    return hashlib.md5(password.encode()).hexdigest()   # VULN


def hash_file_sha1(filepath: str) -> str:
    """
    VH-031 | CWE-327 | Weak SHA-1 Algorithm
    """
    with open(filepath, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()  # VULN


def generate_token(length: int = 32) -> str:
    """
    VH-032 | CWE-338 | Non-Cryptographic PRNG
    random.choice is predictable and must not be used for security tokens.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))  # VULN


def load_session(session_bytes: bytes) -> dict:
    """
    VH-040 | CWE-502 | Insecure Deserialization via pickle
    pickle.loads() with external data may execute arbitrary code.
    """
    return pickle.loads(session_bytes)   # VULN


def load_config(config_str: str) -> dict:
    """
    VH-041 | CWE-502 | yaml.load() without SafeLoader
    Allows code execution through !!python/object tags
    """
    return yaml.load(config_str)   # VULN


def open_file_from_request(filename: str) -> str:
    """
    VH-050 | CWE-22 | Path Traversal
    filename may contain "../../../etc/passwd"
    """
    with open(request.args.get("file")) as f:  # VULN
        return f.read()


def send_report(url: str, data: dict) -> None:
    """
    VH-070 | CWE-295 | SSL Verification Disabled
    verify=False is vulnerable to Man-in-the-Middle attacks.
    """
    import requests
    requests.post(url, json=data, verify=False)   # VULN


# Flask application with debug mode enabled
# VH-080 | CWE-94 | Debug Mode in Production
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.secret_key = secret_key
DEBUG = True   # VULN

@app.route("/search")
def search():
    """
    VH-022 | CWE-94 | Server-Side Template Injection (SSTI)
    User input is injected directly into the Jinja2 template.
    Payload: ?q={{7*7}} or ?q={{config.SECRET_KEY}}
    """
    query    = request.args.get("q", "")
    template = f"<h1>Results for: {query}</h1>"
    return render_template_string(template)   # VULN


@app.route("/debug/error")
def trigger_error():
    """
    VH-081 | CWE-209 | Stack Trace Exposed to the User
    """
    import traceback
    try:
        1 / 0
    except Exception:
        return traceback.print_exc()   # VULN


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")   # VULN — debug=True + binding to 0.0.0.0
