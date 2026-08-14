# 🎓 Security Awareness Quiz

> Interactive CLI security awareness quiz — 22 questions, 8 categories,
> timed mode, grades, and learning resources. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](security_quiz.py)
[![Questions](https://img.shields.io/badge/Questions-22-brightgreen?style=flat-square)](security_quiz.py)

---

## Overview

Security Awareness Quiz tests knowledge across the most important
cybersecurity topics — from phishing to GDPR to malware analysis.
Each question includes a detailed explanation and references.

```bash
# Standard quiz (10 random questions)
python security_quiz.py --name "Marcio"

# All 22 questions
python security_quiz.py --name "Marcio" --n 22

# Filter by category
python security_quiz.py --category phishing --n 5

# Timed mode (30 seconds per question)
python security_quiz.py --timed

# Difficulty filter
python security_quiz.py --difficulty hard

# List available categories
python security_quiz.py --list-categories

# Save result to JSON
python security_quiz.py --name "Marcio" -o result.json
```

---

## Question Categories

| Category               | Questions | Topics                                                        |
| ---------------------- | --------- | ------------------------------------------------------------- |
| **Phishing**           | 4         | Spear phishing, smishing, URL analysis, urgency tactics       |
| **Passwords**          | 3         | Passphrases, password managers, credential stuffing           |
| **Authentication**     | 2         | MFA types, FIDO2 vs SMS vs TOTP security                      |
| **GDPR**               | 3         | 72h notification, right to erasure, sensitive data categories |
| **Network**            | 2         | Public Wi-Fi risks, Man-in-the-Middle attacks                 |
| **Malware**            | 3         | Ransomware, Living-off-the-Land, extension spoofing           |
| **Social Engineering** | 2         | Pretexting, IT impersonation                                  |
| **Work Security**      | 3         | Screen lock, USB baiting, cloud shared responsibility         |

---

## Difficulty Levels

| Level  | Points | Description                                 |
| ------ | ------ | ------------------------------------------- |
| Easy   | 10 pts | Fundamental concepts — accessible to all    |
| Medium | 15 pts | Intermediate — requires practical knowledge |
| Hard   | 20 pts | Advanced — technical depth required         |

---

## Grading

| Grade | Score  | Description                             |
| ----- | ------ | --------------------------------------- |
| A     | >= 90% | Excellent — strong security awareness   |
| B     | >= 75% | Good — solid foundation with minor gaps |
| C     | >= 60% | Average — key areas need reinforcement  |
| D     | >= 50% | Below average — significant gaps        |
| F     | < 50%  | Fail — immediate training required      |

---

## Example Session

```
  SECURITY AWARENESS QUIZ
  Player     : Marcio
  Questions  : 10
  ════════════════════════════════════════════════════════════════════

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [1/10]   Phishing  [Medium]  +15pts

  You receive an email from your bank urgently asking you to
  confirm your account details via a link. What do you do?

  [1] Click the link and confirm details quickly
  [2] Ignore the email and do nothing
  [3] Contact the bank directly via official number and report
  [4] Reply to the email asking for more information

  Answer (1-4): 3

  ✅ CORRECT! +15 points

  💡 Banks NEVER request credentials via email. Urgency is a
  social engineering tactic. Always contact the institution
  via official contacts from their website or card.

  FINAL RESULT — Marcio
  ════════════════════════════════════════════════════════════════════
  Score     : 120/150 (80.0%)
  Grade     : B
  Correct   : 8/10
  Duration  : 142s

  ✅ Good work! Solid foundation with minor areas to improve.

  Areas to reinforce:
  ● GDPR (1 question)
  ● Malware (1 question)

  Learning resources:
  • OWASP Top 10: https://owasp.org/Top10/
  • CNCS Best Practices: https://www.cncs.gov.pt/
  • TryHackMe (free): https://tryhackme.com/
```

---

## Use Cases

### Individual Learning

```bash
# Start with easy questions
python security_quiz.py --difficulty easy --n 10

# Then medium
python security_quiz.py --difficulty medium --n 10

# Challenge yourself with hard
python security_quiz.py --difficulty hard --n 22 --timed
```

### Team Training

```bash
# Generate results for each team member
for name in Alice Bob Carlos Diana; do
  python security_quiz.py --name "$name" --n 15 -o "results/${name}.json"
done

# Compare scores
python -c "
import json, glob
results = [json.load(open(f)) for f in glob.glob('results/*.json')]
results.sort(key=lambda r: -r['percentage'])
for r in results:
    print(f\"{r['player']:<15} {r['grade']}  {r['percentage']:.1f}%\")
"
```

### Phishing Simulation Follow-up

```bash
# Target phishing questions after a phishing exercise
python security_quiz.py --category phishing --n 4
```

---

## JSON Output Format

```json
{
  "player": "Marcio",
  "mode": "normal",
  "date": "2024-01-15T10:30:00",
  "score": 120,
  "max_score": 150,
  "percentage": 80.0,
  "grade": "B",
  "results": [
    {
      "question_id": "PH-001",
      "category": "Phishing",
      "difficulty": "Easy",
      "correct": true,
      "points": 10,
      "time_taken": 8.3
    }
  ]
}
```

---

## Repository Structure

```
security-quiz/
├── security_quiz.py
├── README.md
└── .gitignore
```

---

## References

- [SANS Security Awareness](https://www.sans.org/security-awareness-training/)
- [ENISA Cybersecurity Awareness](https://www.enisa.europa.eu/topics/cybersecurity-education)
- [CNCS — Best Practices](https://www.cncs.gov.pt/boas-praticas/)
- [GDPR — Art. 33 Breach Notification](https://eur-lex.europa.eu/eli/reg/2016/679/oj)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) —  Cybersecurity Specialist, Porto, Portugal*
