# ⚖️ Legal Disclaimer — Subdomain Takeover Checker

## IMPORTANT — READ BEFORE USE

The `subdomain_takeover.py` tool in this repository is intended exclusively for
**authorized security testing, defensive research, and educational purposes**.
It checks subdomains and DNS records for conditions that may indicate a potential
subdomain takeover risk.

---

## Authorized Use

This tool may **only** be used to assess:

- ✅ Domains, subdomains, and DNS zones that you **personally own or administer**
- ✅ Assets for which you have **explicit written authorization** from the legal owner
- ✅ Bug bounty targets that are **within the program's defined scope**
- ✅ Controlled laboratory or training environments
- ✅ Security assessments performed under a valid penetration-testing agreement

Authorization should clearly define the permitted domains, testing methods,
time window, limitations, and emergency contact details.

---

## Prohibited Use

This tool must **NOT** be used for:

- ❌ Enumerating, probing, or testing domains without explicit permission
- ❌ Claiming or attempting to claim third-party cloud resources or services
- ❌ Hosting content through a vulnerable subdomain belonging to another party
- ❌ Accessing, modifying, intercepting, or collecting unauthorized data
- ❌ Disrupting services or causing damage to systems or infrastructure
- ❌ Any malicious, criminal, deceptive, or otherwise unlawful activity

A suspected takeover condition must not be exploited merely to confirm that it
is exploitable. Validation should remain non-invasive unless the asset owner has
explicitly authorized a controlled proof of concept.

---

## Legal Notice

Unauthorized use of this tool may violate:

- **Portugal**: Cybercrime Law (Law No. 109/2009), including Article 7 on unlawful access
- **European Union**: Directive 2013/40/EU on attacks against information systems
- **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **United Kingdom**: Computer Misuse Act 1990
- Other applicable computer crime, privacy, communications, and data-protection laws

Violations may result in **criminal prosecution, civil liability, financial
penalties, and imprisonment**.

This document is provided for general informational purposes and does not
constitute legal advice. Obtain professional legal advice when necessary.

---

## Ethical Responsibility

The author, Márcio Coutinho, provides this tool for **defensive security purposes**:

- Identifying dangling DNS records before they can be abused
- Supporting authorized penetration tests and security assessments
- Conducting bug bounty research within the published scope and rules
- Improving DNS hygiene and cloud-resource lifecycle management
- Supporting educational and academic research

The author accepts **no responsibility** for misuse, unauthorized testing, or
illegal activity performed with this software. By using the tool, you agree to
comply with all applicable laws, contractual requirements, and authorization
boundaries.

---

## Penetration Testing Authorization Template

Before testing any domain, obtain written authorization. Example language:

```
SUBDOMAIN TAKEOVER SECURITY TEST AUTHORIZATION

I, [Client Name], authorize [Tester Name] to perform subdomain takeover
assessment activities on the following domains and subdomains:
[list of authorized domains and subdomains]

Permitted activities: [DNS enumeration, CNAME analysis, HTTP fingerprint checks]
Out of scope: [assets and actions that must not be tested]
Testing window: [dates and times]
Data-handling requirements: [requirements]
Emergency contact: [name and phone number]

Signed: _________________________ Date: _________
```

---

## Reporting Vulnerabilities

If you identify a possible takeover condition on an asset that you are **not
authorized to test**:

1. **Do not claim the referenced service or resource**
2. **Do not upload content or attempt to demonstrate control**
3. Preserve only the minimum non-invasive evidence already observed
4. Report the issue through the organization's responsible-disclosure channel
5. Follow the applicable bug bounty or vulnerability-disclosure policy

---

*Márcio Coutinho — Cybersecurity Specialist · Porto, Portugal*  
*github.com/marciolscoutinho*
