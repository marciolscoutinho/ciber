# ☁️ Cloud Scanner

> Cloud misconfiguration scanner for Terraform static analysis and live AWS checks.
> Detects public exposure, excessive permissions, and missing security controls.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](cloud_scanner.py)
[![CIS](https://img.shields.io/badge/CIS-Cloud%20Benchmarks-orange?style=flat-square)](https://www.cisecurity.org/benchmark)

> **⚠️ Authorized use only.** Scan only cloud environments, accounts, and Infrastructure-as-Code repositories that you own or have explicit written permission to assess.

---

## 📋 Overview

Cloud Scanner performs **static analysis of Terraform files** for AWS, Azure, and Google Cloud Platform resources. It can also run a small set of **live AWS checks** through the AWS CLI when credentials are already configured locally.

The tool is intentionally lightweight: it uses the Python standard library only and is suitable for portfolio projects, lab environments, CI pipelines, and defensive cloud security reviews.

```bash
# Scan Terraform files in the current directory
python cloud_scanner.py . --mode terraform

# Run live AWS checks (requires AWS CLI and configured credentials)
python cloud_scanner.py . --mode aws-live

# Demo mode with synthetic findings
python cloud_scanner.py . --mode demo
```

---

## 🔍 Detection Rules

### AWS Terraform Checks

| Rule ID    | Resource       | Severity    | Description                                                    |
| ---------- | -------------- | ----------- | -------------------------------------------------------------- |
| TF-AWS-001 | Security Group | 🔴 CRITICAL | Ingress rule allows `0.0.0.0/0` on port 22, 3389, or all ports |
| TF-AWS-001 | Security Group | 🟠 HIGH     | Any non-administrative port is open to `0.0.0.0/0`             |
| TF-AWS-002 | S3 Bucket      | 🔴 CRITICAL | ACL is set to `public-read`                                    |
| TF-AWS-003 | S3 Bucket      | 🟠 HIGH     | S3 Block Public Access controls are disabled                   |
| TF-AWS-004 | IAM Policy     | 🔴 CRITICAL | IAM policy grants wildcard actions with `Action: "*"`          |
| TF-AWS-005 | RDS Instance   | 🟠 HIGH     | RDS storage encryption is missing or disabled                  |
| TF-AWS-006 | EC2 Instance   | 🟡 MEDIUM   | `associate_public_ip_address = true`                           |
| TF-AWS-007 | CloudTrail     | 🟠 HIGH     | `enable_logging = false`                                       |

### Azure Terraform Checks

| Rule ID   | Resource        | Severity | Description                                |
| --------- | --------------- | -------- | ------------------------------------------ |
| TF-AZ-001 | Storage Account | 🟠 HIGH  | `allow_blob_public_access = true`          |
| TF-AZ-002 | Storage Account | 🟠 HIGH  | `min_tls_version = "TLS1_0"` or `"TLS1_1"` |

### GCP Terraform Checks

| Rule ID    | Resource      | Severity    | Description                                                               |
| ---------- | ------------- | ----------- | ------------------------------------------------------------------------- |
| TF-GCP-001 | Cloud Storage | 🔴 CRITICAL | Bucket IAM binding grants access to `allUsers` or `allAuthenticatedUsers` |

### AWS Live Checks

| Rule ID      | Service        | Severity    | Description                               |
| ------------ | -------------- | ----------- | ----------------------------------------- |
| AWS-LIVE-001 | S3             | 🔴 CRITICAL | Bucket ACL grants public access           |
| AWS-LIVE-002 | Security Group | 🔴/🟠/🟡    | Security Group ingress allows `0.0.0.0/0` |
| AWS-LIVE-003 | IAM            | 🔴 CRITICAL | Root account has active access keys       |
| AWS-LIVE-004 | IAM            | 🔴 CRITICAL | Root account MFA is not enabled           |
| AWS-LIVE-005 | CloudTrail     | 🔴 CRITICAL | No CloudTrail trail is configured         |
| AWS-LIVE-006 | CloudTrail     | 🟡 MEDIUM   | Trail is not multi-region                 |

---

## 🚀 Usage

### Terraform Mode

```bash
# Scan the current directory
python cloud_scanner.py . --mode terraform

# Scan a specific directory
python cloud_scanner.py ./infrastructure/ --mode terraform

# Scan one Terraform file
python cloud_scanner.py ./main.tf --mode terraform

# Filter by provider
python cloud_scanner.py . --mode terraform --provider aws
python cloud_scanner.py . --mode terraform --provider azure
python cloud_scanner.py . --mode terraform --provider gcp

# JSON output
python cloud_scanner.py . --mode terraform --json -o report.json

# Markdown report
python cloud_scanner.py . --mode terraform -o cloud_report.md
```

### AWS Live Mode

```bash
# Requires: aws configure, AWS SSO, or AWS environment variables
python cloud_scanner.py . --mode aws-live

# Filter AWS findings explicitly
python cloud_scanner.py . --mode aws-live --provider aws
```

### Demo Mode

```bash
# No credentials needed
python cloud_scanner.py . --mode demo
```

---

## 📊 Example Output

```text
  CLOUD SECURITY SCAN SUMMARY
  Target    : ./infrastructure/
  Type      : terraform
  Resources : 8
  Findings  : 8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CRITICAL   ███ 3
  HIGH       ██ 2
  MEDIUM     █ 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cloud Security Score: 32.0/100  [████████████░░░░░░░░░░░░░░░░░░░░░░]
```

---

## 🏗️ Remediation Examples

### Fix: S3 Public Bucket

```hcl
# ❌ Vulnerable
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
  acl    = "public-read"
}

# ✅ Secure
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Fix: Security Group

```hcl
# ❌ Vulnerable
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ Secure
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.10/32"] # Administrator IP only
  }
}
```

### Fix: IAM Policy

```hcl
# ❌ Vulnerable
data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

# ✅ Secure — principle of least privilege
data "aws_iam_policy_document" "app" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
```

---

## 🔚 Exit Codes

| Code | Meaning                                                 |
| ----:| ------------------------------------------------------- |
| `0`  | No findings, only LOW findings, or informational output |
| `1`  | At least one MEDIUM or HIGH finding                     |
| `2`  | At least one CRITICAL finding                           |

---

## 📁 Repository Structure

```text
ciber/
   cloud-scanner
            ├── cloud_scanner.py
            ├── README.md
            ├── LICENSE
            ├── .gitignore
            ├── .markdownlint.json
            ├── test_terraform/
            │            ├── secure.tf
            │            └── vulnerable.tf
            └── .github/
                    └── workflows/
                            └── ci.yml
```

---

## 🔗 References

- [CIS Amazon Web Services Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Terraform Security Best Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Level 5 CET, Porto, Portugal.*
