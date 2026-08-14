#!/usr/bin/env python3
"""
app.py — hack-me CTF
====================
⚠  DELIBERATELY VULNERABLE APPLICATION  ⚠
   Built for educational purposes only.
   Author: Márcio Coutinho — Cybersecurity Specialist
   Date  : 26/09/2025
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, redirect, session, g

app = Flask(__name__)

# ──────────────────────────────────────────────────────────────
# FLAG 1 — Hardcoded secret (CWE-259 / A02:2021)
# A developer left a credential and a secret directly in source.
# You found it. That's the flag.
# ──────────────────────────────────────────────────────────────
app.secret_key    = "dev-secret-dont-use-in-prod"
ADMIN_PASSWORD    = "sup3r_s3cr3t_4dm1n"
FLAG_1            = "FLAG{h4rdc0d3d_s3cr3ts_4r3_4lw4ys_f0und}"   # A02:2021


DATABASE = "hackme.db"


# ── Database helpers ──────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

# ── Home ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>HackMe Corp — Internal Portal</title>
  <style>
    body { font-family: monospace; background:#0d1117; color:#c9d1d9; padding:40px; }
    h1   { color:#ff6b35; }
    a    { color:#58a6ff; text-decoration:none; }
    a:hover { text-decoration:underline; }
    nav  { margin:20px 0; display:flex; gap:20px; }
    .banner { border:1px solid #30363d; padding:16px; border-radius:6px; margin-bottom:20px; }
  </style>
</head>
<body>
  <h1>💀 HackMe Corp — Internal Portal</h1>
  <div class="banner">
    <p>Welcome to the HackMe Corp internal portal.</p>
    <p>This system is for <strong>authorized users only</strong>.</p>
    <!-- TODO: remove debug mode before shipping — @dev -->
  </div>
  <nav>
    <a href="/login">🔐 Login</a>
    <a href="/search">🔍 Search Products</a>
    <a href="/download?file=welcome.txt">📄 Download Report</a>
    <a href="/ping?host=127.0.0.1">📡 Network Ping</a>
    <a href="/admin">🛡 Admin Panel</a>
  </nav>
  <p style="color:#6e7681; font-size:12px;">HackMe Corp v1.0 — Internal Use Only</p>
</body>
</html>
""")


# ── Login — FLAG 2 (SQL Injection / A03:2021) ────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    FLAG 2 — SQL Injection via string concatenation (CWE-89 / A03:2021)
    The username is concatenated directly into the SQL query.
    Payload: username = admin'--
             password = anything
    The flag is stored in the users table as the admin's 'notes' field.
    """
    message = ""
    flag    = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db    = get_db()
        # ⚠ VULNERABILITY: string concatenation in SQL query
        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"

        try:
            row = db.execute(query).fetchone()
        except Exception as e:
            message = f"DB Error: {e}"
            row = None

        if row:
            session["user"] = row["username"]
            flag    = row["notes"]   # Flag hidden in the 'notes' column
            message = f"✅ Welcome, {row['username']}! Notes: {flag}"
        else:
            message = "❌ Invalid credentials."

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Login — HackMe Corp</title>
  <style>
    body  { font-family:monospace; background:#0d1117; color:#c9d1d9; padding:40px; }
    h1    { color:#ff6b35; }
    input { background:#161b22; border:1px solid #30363d; color:#c9d1d9;
            padding:8px 12px; border-radius:4px; width:280px; margin:4px 0; }
    button { background:#ff6b35; color:#fff; border:none; padding:10px 24px;
             border-radius:4px; cursor:pointer; margin-top:8px; }
    .msg  { margin-top:16px; padding:12px; border:1px solid #30363d;
            border-radius:4px; background:#161b22; }
    a     { color:#58a6ff; }
  </style>
</head>
<body>
  <h1>🔐 Login</h1>
  <form method="POST">
    <div><input name="username" placeholder="Username" autocomplete="off"/></div>
    <div><input name="password" placeholder="Password" type="password"/></div>
    <button type="submit">Login</button>
  </form>
  {% if message %}
  <div class="msg">{{ message }}</div>
  {% endif %}
  <p><a href="/">← Back</a></p>
</body>
</html>
""", message=message)


# ── Search — FLAG 3 (SSTI / A03:2021) ────────────────────────

@app.route("/search")
def search():
    """
    FLAG 3 — Server-Side Template Injection (CWE-94 / A03:2021)
    The search query is injected directly into a Jinja2 template string.
    Payload: ?q={{config.SECRET_KEY}}   → reveals the secret key
             ?q={{''.__class__.__mro__[1].__subclasses__()}}  → deeper RCE
    The FLAG_3 variable is accessible via the Jinja2 context.
    Try: ?q={{ FLAG_3 }}
    """
    FLAG_3 = "FLAG{s3rv3r_s1d3_t3mpl4t3_1nj3ct10n_pwn3d}"   # A03:2021
    query  = request.args.get("q", "")

    # ⚠ VULNERABILITY: user input rendered inside a template string
    template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Search — HackMe Corp</title>
  <style>
    body {{ font-family:monospace; background:#0d1117; color:#c9d1d9; padding:40px; }}
    h1   {{ color:#ff6b35; }}
    input {{ background:#161b22; border:1px solid #30363d; color:#c9d1d9;
             padding:8px 12px; border-radius:4px; width:320px; }}
    button {{ background:#238636; color:#fff; border:none; padding:8px 20px;
              border-radius:4px; cursor:pointer; }}
    .result {{ margin-top:20px; padding:12px; border:1px solid #30363d;
               border-radius:4px; background:#161b22; }}
    a {{ color:#58a6ff; }}
  </style>
</head>
<body>
  <h1>🔍 Product Search</h1>
  <form method="GET">
    <input name="q" value="{query}" placeholder="Search products..."/>
    <button type="submit">Search</button>
  </form>
  <div class="result">Results for: {query}</div>
  <p><a href="/">← Back</a></p>
</body>
</html>"""

    return render_template_string(template, FLAG_3=FLAG_3)


# ── Download — FLAG 4 (Path Traversal / A01:2021) ────────────

@app.route("/download")
def download():
    """
    FLAG 4 — Path Traversal (CWE-22 / A01:2021)
    The 'file' parameter is used to open files with no sanitization.
    Payload: ?file=../../secret/flag.txt
    The flag is stored in a file outside the web root.
    """
    filename = request.args.get("file", "welcome.txt")
    base_dir = os.path.join(os.path.dirname(__file__), "files")

    # ⚠ VULNERABILITY: no path sanitization — allows directory traversal
    try:
        filepath = os.path.join(base_dir, filename)
        with open(filepath, "r") as f:
            content = f.read()
    except FileNotFoundError:
        content = f"File not found: {filename}"
    except Exception as e:
        content = f"Error: {e}"

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Download — HackMe Corp</title>
  <style>
    body {{ font-family:monospace; background:#0d1117; color:#c9d1d9; padding:40px; }}
    h1   {{ color:#ff6b35; }}
    pre  {{ background:#161b22; border:1px solid #30363d; padding:16px;
            border-radius:4px; overflow-x:auto; white-space:pre-wrap; }}
    a    {{ color:#58a6ff; }}
  </style>
</head>
<body>
  <h1>📄 File Download</h1>
  <p>Fetching: <code>{{ filename }}</code></p>
  <pre>{{ content }}</pre>
  <p><a href="/">← Back</a></p>
</body>
</html>
""", filename=filename, content=content)


# ── Ping — FLAG 5 (Command Injection / A03:2021) ─────────────

@app.route("/ping")
def ping():
    """
    FLAG 5 — OS Command Injection via os.system() (CWE-78 / A03:2021)
    The 'host' parameter is passed directly to os.system via an f-string.
    Payload: ?host=127.0.0.1; cat secret/flag.txt
             ?host=127.0.0.1 && cat secret/flag.txt
             ?host=127.0.0.1 | cat secret/flag.txt
    """
    host   = request.args.get("host", "127.0.0.1")
    output = ""

    # ⚠ VULNERABILITY: unsanitized input passed to shell command
    try:
        result = subprocess.run(
            f"ping -c 2 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Request timed out."
    except Exception as e:
        output = f"Error: {e}"

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Ping — HackMe Corp</title>
  <style>
    body {{ font-family:monospace; background:#0d1117; color:#c9d1d9; padding:40px; }}
    h1   {{ color:#ff6b35; }}
    input {{ background:#161b22; border:1px solid #30363d; color:#c9d1d9;
             padding:8px 12px; border-radius:4px; width:280px; }}
    button {{ background:#238636; color:#fff; border:none; padding:8px 20px;
              border-radius:4px; cursor:pointer; }}
    pre  {{ background:#161b22; border:1px solid #30363d; padding:16px;
            border-radius:4px; overflow-x:auto; white-space:pre-wrap; }}
    a    {{ color:#58a6ff; }}
  </style>
</head>
<body>
  <h1>📡 Network Ping</h1>
  <form method="GET">
    <input name="host" value="{{ host }}" placeholder="hostname or IP"/>
    <button type="submit">Ping</button>
  </form>
  {% if output %}
  <pre>{{ output }}</pre>
  {% endif %}
  <p><a href="/">← Back</a></p>
</body>
</html>
""", host=host, output=output)


# ── Admin — Broken Access Control (A01:2021) ─────────────────

@app.route("/admin")
def admin():
    """
    Admin panel — accessible without authentication.
    Broken Access Control (A01:2021) — informational, no flag here.
    But it reveals the structure of the app for further attack.
    """
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Admin — HackMe Corp</title>
  <style>
    body {{ font-family:monospace; background:#0d1117; color:#c9d1d9; padding:40px; }}
    h1   {{ color:#ff6b35; }}
    table {{ border-collapse:collapse; width:100%; margin-top:16px; }}
    td,th {{ border:1px solid #30363d; padding:8px 12px; text-align:left; }}
    th    {{ background:#161b22; color:#58a6ff; }}
    a     {{ color:#58a6ff; }}
  </style>
</head>
<body>
  <h1>🛡 Admin Panel</h1>
  <p style="color:#f85149;">⚠ Access control not implemented — anyone can reach this page.</p>
  <table>
    <tr><th>Route</th><th>Vulnerability</th><th>OWASP</th></tr>
    <tr><td>/login</td><td>SQL Injection</td><td>A03:2021</td></tr>
    <tr><td>/search</td><td>SSTI</td><td>A03:2021</td></tr>
    <tr><td>/download</td><td>Path Traversal</td><td>A01:2021</td></tr>
    <tr><td>/ping</td><td>Command Injection</td><td>A03:2021</td></tr>
    <tr><td>app.py</td><td>Hardcoded Secrets</td><td>A02:2021</td></tr>
  </table>
  <p><a href="/">← Back</a></p>
</body>
</html>
""")


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
