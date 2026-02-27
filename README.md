# AWS IAM Hardening for HIPAA Compliance

A practical, step-by-step guide for securing AWS Identity and Access 
Management (IAM) in healthcare cloud environments — written for IT and 
security teams who need to meet HIPAA Technical Safeguard requirements, 
not just generic cloud best practices.

**Built by [Teknikally Speaking](https://github.com/jesmanderson)** — 
Houston-based cloud security and GRC consultancy specializing in 
healthcare.

---

## Why This Repo Exists

HIPAA's Security Rule requires covered entities and business associates 
to implement technical safeguards controlling access to electronic 
Protected Health Information (ePHI). Most healthcare organizations 
running on AWS have IAM environments that grew organically — 
overprivileged roles, stale credentials, no least privilege enforcement, 
and zero governance documentation.

This repo gives you the exact configurations, scripts, and audit 
methodology to close those gaps and produce compliance evidence your 
security officer and auditors can actually use.

---

## HIPAA Technical Safeguard Mapping

Every step in this guide maps to a specific HIPAA requirement:

| Step | HIPAA Standard | Specification |
|------|---------------|---------------|
| Password Policy | Access Control (§164.312(a)(1)) | Unique user identification |
| MFA Enforcement | Access Control (§164.312(a)(1)) | Automatic logoff / Person auth |
| IAM Audit | Audit Controls (§164.312(b)) | Activity review |
| Permissions Boundary | Access Control (§164.312(a)(1)) | Minimum necessary access |
| Access Analyzer | Audit Controls (§164.312(b)) | Information system activity review |

---

## What This Guide Covers

- Configuring the AWS CLI for IAM governance work
- Enforcing a **strong password policy** aligned to HIPAA requirements
- **Requiring MFA** for all human users accessing ePHI environments
- **Auditing IAM users** and generating compliance evidence (CSV reports)
- Implementing **permissions boundaries** to enforce least privilege
- Enabling **Access Analyzer** to detect unintended resource exposure
- Producing a **risk register** with remediation status for audit purposes

---

## Prerequisites

- An AWS account with IAM administrative permissions
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows) installed
- PowerShell (Windows or VS Code terminal)
- Basic familiarity with AWS IAM concepts

---

## Step 1: Install and Configure the AWS CLI

Download and install AWS CLI v2:
https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows

Verify the install:
```powershell
aws --version
```

Configure your access credentials:
```powershell
aws configure
```

Enter your AWS Access Key ID, Secret Access Key, default region 
(e.g. `us-east-1`), and output format (`json` or `table`).

> **HIPAA Note:** Always use a non-root IAM account with only the 
> permissions needed for this task. Never use root credentials for 
> routine operations — this violates HIPAA's minimum necessary access 
> principle.

---

## Step 2: Set a HIPAA-Aligned Password Policy

HIPAA requires unique user identification and person authentication. 
A strong password policy is a foundational control.
```powershell
aws iam update-account-password-policy `
  --minimum-password-length 14 `
  --require-symbols `
  --require-numbers `
  --require-uppercase-characters `
  --require-lowercase-characters `
  --max-password-age 90 `
  --password-reuse-prevention 24 `
  --allow-users-to-change-password
```

This enforces complexity, 90-day rotation, and 24-password reuse 
prevention — all defensible in a HIPAA audit.

---

## Step 3: Enforce MFA for All Human Users

MFA is a critical control for HIPAA person authentication requirements. 
Any user without MFA who has access to ePHI is a compliance gap and a 
breach risk.

Save this as `deny_without_mfa.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAllActionsIfNoMFA",
    "Effect": "Deny",
    "NotAction": [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:GetUser",
      "sts:GetCallerIdentity",
      "sts:GetSessionToken",
      "iam:ChangePassword"
    ],
    "Resource": "*",
    "Condition": { 
      "BoolIfExists": { 
        "aws:MultiFactorAuthPresent": "false" 
      } 
    }
  }]
}
```

Create the policy and attach it to your human users group:
```powershell
aws iam create-policy `
  --policy-name deny-without-mfa `
  --policy-document file://deny_without_mfa.json

aws iam create-group --group-name human-users

aws iam attach-group-policy `
  --group-name human-users `
  --policy-arn arn:aws:iam::<your-account-id>:policy/deny-without-mfa
```

Any user added to `human-users` must enable MFA or they cannot 
access AWS resources.

---

## Step 4: Audit IAM Users and Generate Compliance Evidence

HIPAA Audit Controls (§164.312(b)) require healthcare organizations to 
implement mechanisms to record and examine activity in systems containing 
ePHI. Regular IAM audits are part of that requirement.

The `Audit-MFA.ps1` script in the `scripts/` folder generates a 
MFA compliance report for all IAM users.
```powershell
cd C:\Users\aws-iam-hardening\scripts
.\Audit-MFA.ps1
```

Output example:
```
Alice ❌ has NO MFA — HIPAA compliance gap
Bob ✅ has MFA enabled — compliant
```

CSV reports are saved to the `reports/` folder for use as audit 
evidence. Keep these reports. If you face an HHS OCR investigation, 
documented evidence of regular access reviews is a significant 
mitigating factor.

---

## Step 5: Implement Permissions Boundaries (Least Privilege)

HIPAA's minimum necessary standard requires that users only have access 
to ePHI they need to do their job. Permissions boundaries enforce a 
ceiling on what any IAM user or role can ever be granted.

Create the boundary policy (see `policies/permissions_boundary.json`):
```powershell
aws iam create-policy `
  --policy-name permissions-boundary-base `
  --policy-document file://permissions_boundary.json
```

Apply it when creating new users:
```powershell
aws iam create-user `
  --user-name analyst.jane `
  --permissions-boundary arn:aws:iam::<your-account-id>:policy/permissions-boundary-base
```

---

## Step 6: Enable Access Analyzer

Access Analyzer identifies IAM roles, S3 buckets, KMS keys, and other 
resources that are accessible from outside your account — a critical 
control for preventing unintended ePHI exposure.
```powershell
aws accessanalyzer create-analyzer `
  --analyzer-name account-access-analyzer `
  --type ACCOUNT
```

Review findings in the AWS Console under IAM → Access Analyzer. 
Any finding that touches a resource containing ePHI should be treated 
as a priority remediation item.

---

## Risk Register

Use this format to document remediation status for audit evidence:

| Risk ID | Risk Description | HIPAA Standard | Mitigation Applied | Status |
|---------|-----------------|----------------|--------------------|--------|
| IAM-001 | Users without MFA | §164.312(a)(1) | deny-without-mfa policy enforced, all users in human-users group | Closed |
| IAM-002 | Overprivileged roles | §164.312(a)(1) | Permissions boundary applied to all new users | Closed |
| IAM-003 | No access review process | §164.312(b) | Audit-MFA.ps1 scheduled monthly, reports archived | Closed |

---

## How This Connects to a Full HIPAA Cloud Security Program

IAM hardening is the foundation — but a complete HIPAA Technical 
Safeguard implementation also requires:

- **Encryption** at rest and in transit (§164.312(a)(2)(iv) and §164.312(e)(2)(ii))
- **Audit logging** via CloudTrail and CloudWatch (§164.312(b))
- **Automatic logoff** and session controls
- **Transmission security** — TLS enforcement across all ePHI data flows
- **Contingency planning** — backup, disaster recovery, and emergency access procedures

Additional repos covering these areas are in development. 
Follow for updates.

---

## About Teknikally Speaking

Teknikally Speaking is a Houston-based cybersecurity consultancy 
specializing in cloud security and GRC for healthcare organizations. 
We help healthcare IT teams implement HIPAA-aligned cloud security 
controls — hands-on technical implementation, not just policy documents.

**Services:** HIPAA Cloud Security Assessments · AWS IAM Governance · 
Cloud Security Posture Management · GRC Advisory

[LinkedIn] | 
[Substack](#) |
