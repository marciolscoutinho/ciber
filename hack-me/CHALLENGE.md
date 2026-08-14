# 🏁 CHALLENGE.md — hack-me CTF

> Read this before you start. Seriously.

---

## Flag Format

All flags follow this pattern:

```
FLAG{s0m3_m3ss4g3_h3r3}
```

When you find one, you'll know.

---

## Rules

1. **No brute force** — all flags are exploitable through a single, clean vulnerability. If you're brute-forcing, you're on the wrong path.
2. **No source code peeking** — the whole point is black-box recon + exploitation. Clone the repo, run the Docker container, attack the running app.
3. **Writeups welcome** — if you solve all 5, open an Issue with your methodology. Reading others' approaches is how we all improve.
4. **Be ethical** — this is a lab environment. Practice the mindset, not just the keystrokes.

---

## The 5 Flags

### 🔴 FLAG 1 — "Some things shouldn't be in code"

**Difficulty:** Easy  
**Category:** A02:2021 — Cryptographic Failures  
**Hint:** You don't need to run the app to find this one. Look carefully at what the developer left behind in the source.

---

### 🔴 FLAG 2 — "Who are you, really?"

**Difficulty:** Medium  
**Category:** A03:2021 — Injection  
**Hint:** The login form trusts you too much. What if your username was a question?

---

### 🟠 FLAG 3 — "The server will tell you anything"

**Difficulty:** Medium  
**Category:** A03:2021 — Injection  
**Hint:** The search endpoint reflects your input. What happens when your input is more than text?

---

### 🟠 FLAG 4 — "Files have no secrets from a determined path"

**Difficulty:** Medium  
**Category:** A01:2021 — Broken Access Control  
**Hint:** The download utility accepts a filename parameter. Where does `../` take you?

---

### 🔴 FLAG 5 — "The shell listens to everyone"

**Difficulty:** Hard  
**Category:** A03:2021 — Injection (OS)  
**Hint:** The ping tool runs a system command. What do `;`, `|`, and `&&` mean to a shell?

---

## Recon Checklist

Before attacking, map the app:

```
[ ] Identify all routes and parameters
[ ] Check HTTP response headers for information disclosure
[ ] Review what input fields exist and what they accept
[ ] Look for comments in HTML source
[ ] Try unexpected input types (numbers where strings expected, etc.)
[ ] Think about what happens server-side for each request
```

---

## Tools You Might Use

```bash
curl -s http://localhost:5000/login -d "username=test&password=test"
curl -v http://localhost:5000/download?file=report.txt
curl -G http://localhost:5000/search --data-urlencode "q=test"
```

No Metasploit needed. Burp Suite helps. `curl` is enough.

---

## Scoring

| Flag      | Points   |
| --------- |:--------:|
| FLAG 1    | 100      |
| FLAG 2    | 200      |
| FLAG 3    | 200      |
| FLAG 4    | 200      |
| FLAG 5    | 300      |
| **Total** | **1000** |

---

## Solutions

Solutions are documented in [`SOLUTIONS.md`](SOLUTIONS.md).  
**Don't open it until you've genuinely tried.** The learning is in the struggle.

---

*Built by Márcio Coutinho — Cybersecurity Specialist · Porto, Portugal*
