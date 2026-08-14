#!/usr/bin/env python3
"""
security_quiz.py — Security Awareness Quiz v1.0.0
==================================================
Interactive security awareness quiz.
Covers: phishing, passwords, GDPR, networks, social engineering, and malware.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 12/08/2025
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, random, sys, time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BLUE="\033[94m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
  ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
  ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝{C.RESET}
{C.DIM}  v{__version__} — Security Awareness Quiz | Phishing · Passwords · GDPR · Malware{C.RESET}
"""

SEP  = "━"*68
SEP2 = "═"*68

# ══════════════════════════════════════════════════════════════════════════════
# QUESTION DATABASE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Question:
    id:          str
    category:    str
    difficulty:  str      # Easy / Medium / Hard
    question:    str
    options:     List[str]
    correct:     int      # index in options (0-based)
    explanation: str
    points:      int = 10
    reference:   str = ""

QUESTIONS: List[Question] = [

    # ── PHISHING ──────────────────────────────────────────────────────────
    Question('PH-001', 'Phishing', 'Easy',
        'You receive an email from your bank asking you to urgently confirm your account details through a link. What should you do?',
        ['Click the link and confirm the details quickly', 'Ignore the email and do nothing', 'Contact the bank directly using its official number and report the email', 'Reply to the email asking for more information'],
        2,
        'Banks NEVER ask for credentials by email. Urgency is a social engineering tactic. Always contact the institution using the official contact details on its website or card. Report the email to the security team or the appropriate authority.',
        10, 'OWASP: Social Engineering'),

    Question('PH-002', 'Phishing', 'Medium',
        'Which of these URLs is most likely to be legitimate for accessing your bank?',
        ['http://banco-seguro.bankexample.pt', 'https://bankexample.pt/conta', 'https://bankexample-login.pt/secure', 'http://bankexample.pt.acesso-conta.com'],
        1,
        "The main domain (bankexample.pt) should be the root domain of the URL. Suspicious constructions such as 'bankexample.pt.acesso-conta.com' are a clear phishing indicator — the root domain is 'acesso-conta.com', not 'bankexample.pt'. HTTPS is necessary but not sufficient to guarantee legitimacy.",
        15, 'NCSC: Phishing guidance'),

    Question('PH-003', 'Phishing', 'Hard',
        "What is 'spear phishing'?",
        ['A type of malware that spreads by email', 'Generic phishing sent in bulk to thousands of people', 'A highly personalized phishing attack targeting a specific individual or organization', 'A phishing attack that uses SMS instead of email'],
        2,
        "Spear phishing is highly personalized — the attacker researches the victim (LinkedIn, social media, news) to create a convincing email using real context such as names, companies, and projects. Its success rate is much higher than generic phishing. When the target is a senior executive, it is called 'whaling'.",
        20, 'MITRE ATT&CK: T1566.001'),

    Question('PH-004', 'Phishing', 'Medium',
        "You receive an SMS from 'CTT' with a link to track a parcel, but you have not ordered anything. What is it?",
        ['It may be legitimate — CTT always sends SMS messages', 'Probably smishing (SMS phishing) — do not click the link', 'A system error — you can safely ignore it', 'A ransomware attack delivered by SMS'],
        1,
        'Smishing is phishing via SMS. It is particularly effective because people often trust SMS messages more, and small screens make URL verification harder. If you do not recognize the parcel, go directly to the official CTT website (ctt.pt) and track it there.',
        10, 'CERT.PT: Smishing'),

    # ── PASSWORDS ─────────────────────────────────────────────────────────
    Question('PW-001', 'Passwords', 'Easy',
        'Which of these is the strongest password?',
        ['Password123!', 'p4$$w0rd', 'Th3-M4r!n3iro-C4nt4-B3m-2024', 'qwerty123'],
        2,
        "Long passphrases (3+ random words with numbers and symbols) are generally stronger and easier to remember than obvious character substitutions such as 'p4$$w0rd'. Length is more important than superficial complexity. Option C has approximately 65 bits of entropy versus about 28 bits for option B.",
        10, 'NIST SP 800-63B'),

    Question('PW-002', 'Passwords', 'Medium',
        'What is a password manager used for?',
        ['To store passwords in plain text inside a secure file', 'To generate and store unique, complex passwords for each service', 'To synchronize the same password across all services', 'To recover forgotten passwords by contacting support'],
        1,
        'Password managers such as Bitwarden, 1Password, and KeePass allow you to use unique, long, random passwords for every service, eliminating password-reuse risk. They store passwords in encrypted form protected by a master password. Password reuse is a major risk: if one service is compromised, reused credentials can expose other accounts through credential stuffing.',
        15, 'ENISA: Password Management'),

    Question('PW-003', 'Passwords', 'Hard',
        "What is a 'credential stuffing' attack?",
        ['Brute-forcing every possible password combination', 'Using lists of credentials compromised in previous breaches to try to access other services', "Guessing a password from the victim's personal information", 'Intercepting credentials on a public Wi-Fi network'],
        1,
        'Credential stuffing exploits password reuse. Attackers obtain credential lists from previous breaches (for example RockYou or Collection #1) and automatically test them against other services such as streaming platforms, email, or banking sites. The solution is to use a unique password for every service plus MFA. You can check whether your data has appeared in known breaches at haveibeenpwned.com.',
        20, 'OWASP: Credential Stuffing'),

    # ── AUTHENTICATION ────────────────────────────────────────────────────
    Question('MFA-001', 'Authentication', 'Easy',
        'What is two-factor or multi-factor authentication (2FA/MFA)?',
        ['Using two different passwords for the same service', 'Confirming your identity using two different types of factors (something you know + something you have)', 'Having two accounts on the same service', 'Logging in on two devices at the same time'],
        1,
        'MFA combines at least two different factor types: something you KNOW (password), something you HAVE (phone or hardware token), and something you ARE (biometrics). Even if the password is compromised, the attacker still needs the additional factor. Microsoft has reported that MFA can prevent the overwhelming majority of account-compromise attempts.',
        10, 'NIST SP 800-63B'),

    Question('MFA-002', 'Authentication', 'Medium',
        'Which is the most secure form of second authentication factor?',
        ['SMS OTP code', 'Email confirmation link', 'TOTP (Google Authenticator, Authy)', 'FIDO2/WebAuthn physical security key (YubiKey)'],
        3,
        'FIDO2/WebAuthn hardware keys such as YubiKey are the strongest option here because they are phishing-resistant and bind authentication to the legitimate domain. TOTP is strong but can still be phished through real-time relay attacks. SMS is weaker because it can be exposed to SIM-swapping and SS7-related attacks. Avoid SMS for MFA when stronger alternatives are available.',
        20, 'FIDO Alliance: FIDO2'),

    # ── GDPR ──────────────────────────────────────────────────────────────
    Question('RGPD-001', 'GDPR', 'Easy',
        'Under the GDPR, when must an organization notify the supervisory authority after becoming aware of a personal data breach?',
        ['Immediately, at the exact moment the breach is discovered', 'Within 72 hours of becoming aware of it', 'Within 30 days of becoming aware of it', 'Only if sensitive data such as health or financial data is involved'],
        1,
        "GDPR Article 33 establishes a 72-hour deadline for notifying the supervisory authority (CNPD in Portugal) after the organization becomes aware of a personal data breach, unless the breach is unlikely to result in a risk to individuals' rights and freedoms. If notification is delayed, the reasons for the delay must be provided. When the breach is likely to result in a high risk to affected individuals, they may also need to be informed under Article 34.",
        15, 'GDPR Art. 33'),

    Question('RGPD-002', 'GDPR', 'Medium',
        "What is the 'right to be forgotten' under the GDPR?",
        ['The right to forget your password', 'The right to request the erasure of personal data in certain circumstances', 'The right not to receive marketing communications', 'The right to keep online purchases private'],
        1,
        "The 'right to erasure' under GDPR Article 17 allows a data subject to request deletion of personal data in certain circumstances, such as when the data is no longer necessary, consent has been withdrawn, or the data has been processed unlawfully. The right is not absolute and can be limited by legal obligations or public-interest grounds. Organizations generally have one month to respond to a data-subject request.",
        15, 'GDPR Art. 17'),

    Question('RGPD-003', 'GDPR', 'Hard',
        'Which of these is considered a special category of personal data under the GDPR?',
        ['First and last name', 'Professional email address', 'Health data and sexual orientation', 'Mobile phone number'],
        2,
        "GDPR Article 9 covers special categories of personal data, including racial or ethnic origin, political opinions, religious or philosophical beliefs, trade-union membership, genetic data, biometric data used for identification, health data, and data concerning a person's sex life or sexual orientation. Processing these categories requires an applicable legal condition and additional safeguards.",
        20, 'GDPR Art. 9'),

    # ── NETWORK & WI-FI ───────────────────────────────────────────────────
    Question('NET-001', 'Network', 'Easy',
        'You are in a café using an open public Wi-Fi network. What is the safest option?',
        ['Use the Wi-Fi normally — the café protects the network', 'Use only HTTPS and a VPN for additional protection', 'Avoid all online activity completely', 'Turn off Wi-Fi and use mobile data for sensitive activity'],
        3,
        'Public Wi-Fi should be treated as untrusted because other users on the network may attempt to intercept traffic. For sensitive activities such as banking or work email, mobile data is generally the safer option. If you must use public Wi-Fi, a VPN can add transport protection. HTTPS protects application content in transit but does not conceal all metadata about your connections.',
        10, 'NCSC: Public Wi-Fi'),

    Question('NET-002', 'Network', 'Medium',
        "What is a 'Man-in-the-Middle' (MitM) attack?",
        ['An attack in which the attacker is physically located between the victim and the server', 'An attack in which the attacker intercepts communications between two parties without their knowledge', 'A type of malware installed in the middle of the operating system', 'A social engineering attack that uses a human intermediary'],
        1,
        'In a MitM attack, the attacker places themselves between the victim and the legitimate service and may be able to read or modify traffic in real time. Techniques can include ARP poisoning on local networks, rogue access points, and SSL stripping. Proper HTTPS validation and mechanisms such as certificate pinning in appropriate applications can reduce MitM risk. Network-monitoring tools such as Wireshark can help investigate suspicious traffic.',
        15, 'OWASP: MitM Attack'),

    # ── MALWARE ───────────────────────────────────────────────────────────
    Question('MW-001', 'Malware', 'Easy',
        "You receive an email attachment named 'invoice_2024.pdf.exe'. What is it?",
        ['A normal PDF — .exe is a compression extension', 'Very likely malware — executables disguised as documents are a classic technique', 'A corrupted file that should simply be deleted', 'A PDF that requires a special plugin to open'],
        1,
        "A double extension such as .pdf.exe is a classic malware-disguise technique. Windows may hide known file extensions, making a file such as 'invoice_2024.pdf.exe' appear to be 'invoice_2024.pdf'. An .exe file is executable code, so executables from unknown sources should not be opened. Enable the display of file extensions in File Explorer and verify filenames carefully.",
        10, 'CERT.PT: Malware'),

    Question('MW-002', 'Malware', 'Medium',
        'What distinguishes ransomware from many other types of malware?',
        ['Ransomware silently steals data without the victim knowing', "Ransomware encrypts the victim's files and demands payment for decryption", 'Ransomware affects only large companies, not individual users', 'Ransomware is a virus that spreads only through USB drives'],
        1,
        'Ransomware commonly encrypts files or systems and demands a ransom, often in cryptocurrency, for recovery or a decryption key. Well-known examples include WannaCry, REvil, and LockBit. Protective measures include regular offline backups following the 3-2-1 principle, timely patching, EDR, and avoiding suspicious links or attachments. Paying a ransom does not guarantee recovery and can finance criminal operations.',
        15, 'CISA: Ransomware Guide'),

    Question('MW-003', 'Malware', 'Hard',
        "What does 'living off the land' (LotL) mean in malware or intrusion activity?",
        ['Malware that uses system resources such as CPU and RAM for cryptocurrency mining', 'A technique in which an attacker uses legitimate operating-system tools to avoid detection', 'Attacks that work only while the device is connected to the internet', 'Malware that spreads through physical network cables'],
        1,
        'Living off the land involves using legitimate, preinstalled system tools to conduct malicious activity, such as PowerShell, WMI, certutil, mshta, and regsvr32 on Windows, or bash, curl, and cron on Linux. This can be harder to detect because trusted system processes are being abused. Detection approaches include Sysmon, EDR behavioral analytics, and monitoring suspicious use of LOLBins.',
        20, 'MITRE ATT&CK: Defense Evasion'),

    # ── SOCIAL ENGINEERING ────────────────────────────────────────────────
    Question('SE-001', 'Social Engineering', 'Easy',
        'Someone calls claiming to be from IT support and says they need your password to fix an urgent problem. What should you do?',
        ['Provide the password — legitimate support needs it to access the system', "Ask for the person's name and call back using the official support number", 'Refuse to provide it — legitimate IT support should never need your password', 'Provide a temporary password'],
        2,
        'Legitimate IT support should never need your password. Support staff can reset credentials or use approved remote-support tools when necessary. A request for your password is a strong warning sign of social engineering or an attempted compromise. Security policy should prohibit sharing passwords, including with colleagues or managers.',
        10, 'SANS: Social Engineering'),

    Question('SE-002', 'Social Engineering', 'Medium',
        "What is 'pretexting' in social engineering?",
        ['Sending an email containing deceptive text', 'Creating a convincing false identity or scenario to manipulate a victim into providing information', 'Using encrypted text to communicate with other attackers', 'Leaving an infected USB drive in a public place for someone to use'],
        1,
        "Pretexting involves creating a believable false scenario or identity. Examples include impersonating an auditor, new employee, supplier, bank representative, or police officer. Attackers may use information collected through OSINT, LinkedIn, or social media to make the pretext credible. Leaving an infected USB drive for someone to find is 'baiting', not pretexting.",
        15, 'OWASP: Social Engineering'),

    # ── WORKPLACE SECURITY ────────────────────────────────────────────────
    Question('WK-001', 'Work Security', 'Easy',
        'You leave your desk to go to the restroom and your PC remains unlocked. What should you have done?',
        ['Nothing — the office is a secure environment', 'Lock the screen (Windows+L or Ctrl+Cmd+Q on Mac) before leaving', 'Ask a colleague to watch the PC', 'Close all application windows before leaving'],
        1,
        'Clear-desk and clear-screen practices are fundamental workplace security controls. Insider threats and accidental misuse remain possible even in an office. An unlocked workstation could be used to access data, install malware, copy information, or send messages under your identity. Configure automatic screen locking after a short period of inactivity as an additional safeguard.',
        10, 'ISO 27001: A.11.2.9'),

    Question('WK-002', 'Work Security', 'Medium',
        'You find a USB drive in the company car park. What should you do?',
        ['Connect it to your PC to see what it contains and return it if possible', 'Take it home and inspect it on your personal PC', 'Give it to the IT department without connecting it to any device', 'Throw it away — if it is lost, it belongs to nobody'],
        2,
        'Abandoned USB drives are a classic baiting technique and can contain malicious code. Research has repeatedly shown that people often connect found USB devices. Give the device to IT without plugging it in. Security teams can analyze removable media using isolated systems or controlled sandboxes. Never connect unknown storage devices to work or personal computers.',
        15, 'NIST: Removable Media'),

    # ── CLOUD ─────────────────────────────────────────────────────────────
    Question('CL-001', 'Cloud', 'Medium',
        'What is the shared responsibility model in cloud computing?',
        ['The cloud provider (AWS/Azure/GCP) is responsible for all security', 'The customer is responsible for all security, including physical infrastructure', 'The provider is responsible for infrastructure security; the customer is responsible for data and configuration security', 'Security responsibility is always split exactly 50/50 between provider and customer'],
        2,
        'Under the cloud shared-responsibility model, the PROVIDER (AWS/Azure/GCP) is generally responsible for the security of the underlying physical infrastructure, networking, facilities, and service platform, while the CUSTOMER remains responsible for areas such as data, identities, access controls, service configuration, applications, and operating-system patching where applicable. Public storage buckets, overly open security groups, and permissive IAM configurations are typically customer-side risks.',
        20, 'AWS: Shared Responsibility Model'),

    # ── INCIDENT RESPONSE ─────────────────────────────────────────────────
    Question('IR-001', 'Incident Response', 'Easy',
        'You believe your PC has been infected with malware. What is the correct first step?',
        ['Install antivirus software and run a full scan', 'Disconnect the PC from the network (Ethernet and Wi-Fi) to limit propagation', 'Back up your data immediately', 'Restart the PC to clear memory'],
        1,
        "Isolation is the first priority — disconnecting the system from the network can prevent malware from communicating with command-and-control infrastructure, spreading to other systems, exfiltrating data, or receiving further instructions. After isolation, report the incident to IT or the CSIRT, preserve evidence where possible, avoid unnecessary rebooting, and follow the organization's incident-response procedure.",
        15, 'NIST SP 800-61: Incident Handling'),

]

# Categories and difficulty levels
CATEGORIES = sorted(set(q.category for q in QUESTIONS))
DIFFICULTIES = ["Easy","Medium","Hard"]

# ══════════════════════════════════════════════════════════════════════════════
# QUIZ ENGINE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class QuizResult:
    question:  Question
    answered:  int       # selected index
    correct:   bool
    time_taken:float

@dataclass
class QuizSession:
    player:    str
    mode:      str
    results:   List[QuizResult] = field(default_factory=list)
    start_time:float = 0.0

    @property
    def score(self) -> int:
        return sum(q.question.points for q in self.results if q.correct)

    @property
    def max_score(self) -> int:
        return sum(q.question.points for q in self.results)

    @property
    def percentage(self) -> float:
        return (self.score / self.max_score * 100) if self.max_score else 0.0

    @property
    def grade(self) -> str:
        pct = self.percentage
        if pct >= 90: return "A"
        if pct >= 75: return "B"
        if pct >= 60: return "C"
        if pct >= 50: return "D"
        return "F"


def select_questions(n: int = 10, category: str = None,
                      difficulty: str = None,
                      shuffle: bool = True) -> List[Question]:
    pool = QUESTIONS[:]
    if category:
        pool = [q for q in pool if q.category.lower() == category.lower()]
    if difficulty:
        pool = [q for q in pool if q.difficulty.lower() == difficulty.lower()]
    if shuffle:
        random.shuffle(pool)
    return pool[:n]


def display_question(q: Question, num: int, total: int) -> None:
    diff_col = {"Easy":C.GREEN,"Medium":C.YELLOW,"Hard":C.RED}.get(q.difficulty,C.DIM)
    print(f"\n{SEP}")
    print(f"  {C.DIM}[{num}/{total}]{C.RESET}  "
          f"📂 {C.CYAN}{q.category}{C.RESET}  "
          f"{diff_col}[{q.difficulty}]{C.RESET}  "
          f"{C.DIM}+{q.points}pts{C.RESET}")
    print(f"\n  {C.BOLD}{q.question}{C.RESET}\n")
    for i, opt in enumerate(q.options):
        print(f"  {C.CYAN}[{i+1}]{C.RESET} {opt}")


def get_answer(num_options: int) -> int:
    while True:
        try:
            val = input(f"\n  {C.DIM}Answer (1-{num_options}): {C.RESET}").strip()
            idx = int(val) - 1
            if 0 <= idx < num_options:
                return idx
            print(f"  {C.RED}Invalid option. Enter a number between 1 and {num_options}.{C.RESET}")
        except (ValueError, KeyboardInterrupt, EOFError):
            print(f"\n  {C.YELLOW}Quiz interrupted.{C.RESET}")
            sys.exit(0)


def show_result(result: QuizResult) -> None:
    if result.correct:
        print(f"\n  {C.GREEN}{C.BOLD}✅ CORRECT! +{result.question.points} points{C.RESET}")
    else:
        correct_opt = result.question.options[result.question.correct]
        print(f"\n  {C.RED}{C.BOLD}❌ WRONG!{C.RESET}")
        print(f"  {C.DIM}Correct answer:{C.RESET} {C.GREEN}{correct_opt}{C.RESET}")

    print(f"\n  {C.CYAN}💡 Explanation:{C.RESET}")
    # Wrap explanation at 65 characters
    words = result.question.explanation.split()
    line  = "  "
    for word in words:
        if len(line) + len(word) > 67:
            print(line)
            line = "  " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    if result.question.reference:
        print(f"\n  {C.DIM}Ref: {result.question.reference}{C.RESET}")
    time.sleep(0.5)


def run_quiz(session: QuizSession, questions: List[Question],
              timed: bool = False, time_limit: int = 30) -> None:
    session.start_time = time.time()
    total = len(questions)

    for i, q in enumerate(questions, 1):
        display_question(q, i, total)

        if timed:
            print(f"  {C.YELLOW}⏱ {time_limit} seconds to answer!{C.RESET}")

        t0  = time.time()
        ans = get_answer(len(q.options))
        elapsed = time.time() - t0

        # Timeout
        if timed and elapsed > time_limit:
            print(f"  {C.RED}⏰ Time is up!{C.RESET}")
            correct = False
        else:
            correct = (ans == q.correct)

        result = QuizResult(q, ans, correct, elapsed)
        session.results.append(result)
        show_result(result)


# ══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════════════════

def print_final_report(session: QuizSession) -> None:
    grade_col = {
        "A": C.GREEN, "B": C.GREEN, "C": C.YELLOW,
        "D": C.YELLOW, "F": C.RED
    }.get(session.grade, C.DIM)

    duration = time.time() - session.start_time
    correct  = sum(1 for r in session.results if r.correct)
    total    = len(session.results)

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}FINAL RESULT — {session.player}{C.RESET}")
    print(SEP2)
    print(f"  Score      : {C.BOLD}{session.score}/{session.max_score}{C.RESET} "
          f"({session.percentage:.1f}%)")
    print(f"  Grade      : {grade_col}{C.BOLD}{session.grade}{C.RESET}")
    print(f"  Correct    : {correct}/{total}")
    print(f"  Duration   : {duration:.0f}s")
    print(SEP)

    # Grade message
    messages = {
        "A": f"{C.GREEN}🏆 Excellent! You demonstrate strong cybersecurity awareness.{C.RESET}",
        "B": f"{C.GREEN}✅ Bom trabalho! Alguns points a melhorar mas boa base.{C.RESET}",
        "C": f"{C.YELLOW}⚠️  Fair result. Reinforce the fundamental concepts.{C.RESET}",
        "D": f"{C.YELLOW}📚 More training is recommended. Review the reference materials.{C.RESET}",
        "F": f"{C.RED}🚨 Attention! Significant knowledge gaps may represent a security risk.{C.RESET}",
    }
    print(f"\n  {messages.get(session.grade, '')}")

    # Areas to improve
    wrong = [r for r in session.results if not r.correct]
    if wrong:
        print(f"\n  {C.BOLD}Areas to reinforce:{C.RESET}")
        cats = set(r.question.category for r in wrong)
        for cat in cats:
            cat_wrong = [r for r in wrong if r.question.category == cat]
            print(f"  {C.YELLOW}●{C.RESET} {cat} ({len(cat_wrong)} question(s))")

    # Resources
    print(f"\n  {C.BOLD}Learning resources:{C.RESET}")
    print(f"  {C.DIM}• OWASP Top 10: https://owasp.org/Top10/{C.RESET}")
    print(f"  {C.DIM}• CNCS Best Practices: https://www.cncs.gov.pt/{C.RESET}")
    print(f"  {C.DIM}• TryHackMe (free): https://tryhackme.com/{C.RESET}")
    print(f"  {C.DIM}• SANS Security Awareness: https://www.sans.org/security-awareness-training/{C.RESET}")
    print(SEP2)


def save_result(session: QuizSession, path: str) -> None:
    data = {
        "player":     session.player,
        "mode":       session.mode,
        "date":       datetime.now().isoformat(),
        "score":      session.score,
        "max_score":  session.max_score,
        "percentage": round(session.percentage, 1),
        "grade":      session.grade,
        "results": [{
            "question_id": r.question.id,
            "category":    r.question.category,
            "difficulty":  r.question.difficulty,
            "correct":     r.correct,
            "points":      r.question.points if r.correct else 0,
            "time_taken":  round(r.time_taken, 1),
        } for r in session.results],
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"\n  {C.GREEN}[✓] Result saved: {path}{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="security-quiz",
        description="Security Awareness Quiz — Phishing · Passwords · GDPR · Malware")
    parser.add_argument("--name",      default="Anonymous", help="Player name")
    parser.add_argument("--n",         type=int, default=10,
        help="Number of questions (default: 10)")
    parser.add_argument("--category",  choices=[c.lower().replace(" ","_") for c in CATEGORIES],
        help="Filter by category")
    parser.add_argument("--difficulty",choices=["easy","medium","hard"],
        help="Filter by difficulty")
    parser.add_argument("--timed",     action="store_true",
        help="Timed mode (30s per question)")
    parser.add_argument("--no-shuffle",action="store_true")
    parser.add_argument("-o","--output",help="Save result as JSON")
    parser.add_argument("--list-categories", action="store_true")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version",   action="version", version=f"security-quiz {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.list_categories:
        print(f"\n  {C.BOLD}Available categories:{C.RESET}")
        for cat in CATEGORIES:
            count = sum(1 for q in QUESTIONS if q.category == cat)
            print(f"  {C.CYAN}●{C.RESET} {cat:<20} ({count} questions)")
        print(f"\n  {C.BOLD}Total:{C.RESET} {len(QUESTIONS)} questions")
        return

    # Map difficulty argument
    diff_map = {"easy":"Easy","medium":"Medium","hard":"Hard"}
    difficulty = diff_map.get(args.difficulty) if args.difficulty else None
    category   = args.category.replace("_"," ").title() if args.category else None

    questions = select_questions(
        n          = args.n,
        category   = category,
        difficulty = difficulty,
        shuffle    = not args.no_shuffle,
    )

    if not questions:
        print(f"  {C.RED}No questions found with the selected filters.{C.RESET}")
        sys.exit(1)

    # Introduction
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SECURITY AWARENESS QUIZ{C.RESET}")
    print(f"  Player     : {args.name}")
    print(f"  Questions  : {len(questions)}")
    if category:
        print(f"  Category   : {category}")
    if difficulty:
        print(f"  Difficulty : {difficulty}")
    if args.timed:
        print(f"  Mode       : {C.YELLOW}TIMED (30s/question){C.RESET}")
    print(SEP2)
    input(f"\n  {C.DIM}Press ENTER to start...{C.RESET}")

    session = QuizSession(player=args.name, mode="timed" if args.timed else "normal")
    run_quiz(session, questions, timed=args.timed)
    print_final_report(session)

    if args.output:
        save_result(session, args.output)


if __name__ == "__main__":
    main()
