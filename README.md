# AWS IAM Hardening Project

This project is a **step-by-step AWS IAM hardening guide**.  
It’s written in **plain language** so new engineers can learn how to secure AWS Identity and Access Management (IAM) using the AWS CLI and PowerShell.

**The workflow:**  
Audit your AWS users → Fix security gaps (like missing MFA) → Collect evidence for compliance.

---

## What You’ll Learn
- How to install and configure the AWS CLI  
- How to set a **strong password policy**  
- How to **require MFA** (multi-factor authentication)  
- How to **audit IAM users** (who has MFA, who doesn’t)  
- How to **save audit reports (CSV)** for compliance evidence  
- How this maps back to **compliance frameworks** like ISO 27001, SOC 2, and CIS Controls  

---

## Prerequisites
- An AWS account (with IAM permissions)  
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows) installed  
- PowerShell (Windows or VS Code terminal)  

---

### **Step 1: Install the AWS CLI**

1. Download & install the AWS CLI v2:  
    https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows  

2. Verify install in PowerShell:
   ```powershell
   aws --version

You should see something like:
`aws-cli/2.15.0 ...`

---

### **Step 2: Configure Your AWS Access**

1. In PowerShell, run:

   ```powershell
   aws configure
   ```

2. Enter:

   * AWS Access Key ID
   * AWS Secret Access Key
   * Default region (e.g., `us-east-1`)
   * Output format (choose `table` or `json`)

>You get these keys from your AWS account → *IAM → Users → Security credentials → Create access key.*
(Use a **non-root account** if possible.)

---

### **Step 3: Create a Strong Password Policy**

Run this once to enforce strong passwords for all IAM users:

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

**This enforces complexity, rotation, and reuse prevention.**

---

### **Step 4: Enforce MFA for Human Users**

We want every user to have MFA enabled before they can do anything.

1. Save this policy JSON as `deny_without_mfa.json`:

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
       "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
     }]
   }
   ```

2. Create the policy in AWS:

   ```powershell
   aws iam create-policy `
     --policy-name deny-without-mfa `
     --policy-document file://deny_without_mfa.json
   ```

3. Create a **group for human users** and attach the policy:

   ```powershell
   aws iam create-group --group-name human-users
   aws iam attach-group-policy `
     --group-name human-users `
     --policy-arn arn:aws:iam::<your-account-id>:policy/deny-without-mfa
   ```

>Any user added to `human-users` must enable MFA or they won’t be able to use AWS.

---

### **Step 5: Audit Existing Users (Who Has MFA?)**

You don’t need to copy code into the console each time.
We save the audit script as `Audit-MFA.ps1` in the `scripts/` folder.

1. Open PowerShell (or VS Code terminal).
2. Go to the scripts folder:

   ```powershell
   cd C:\Users\aws-iam-hardening\scripts
   ```
3. Run the script:

   ```powershell
   .\Audit-MFA.ps1
   ```

**You’ll see a list of users and their MFA status, like:**

```
Alice ❌ has NO MFA
Bob ✅ has MFA enabled
```

The script can also be extended to save results into a CSV file for compliance evidence (see `reports/` folder).

---

### **Step 6: (Optional but Powerful) Permissions Boundary**

This limits how much power any new user/role can get.

1. Save `permissions_boundary.json` (see [policies/](policies/)).
2. Create the boundary policy:

   ```powershell
   aws iam create-policy `
     --policy-name permissions-boundary-base `
     --policy-document file://permissions_boundary.json
   ```
3. When creating new users/roles, attach the boundary:

   ```powershell
   aws iam create-user `
     --user-name analyst.jane `
     --permissions-boundary arn:aws:iam::<your-account-id>:policy/permissions-boundary-base
   ```

---

### **Step 7: Enable Access Analyzer**

Access Analyzer helps find resources shared publicly or across accounts:

```powershell
aws accessanalyzer create-analyzer `
  --analyzer-name account-access-analyzer `
  --type ACCOUNT
```

---

## Risk Register Example

| Risk ID | Risk Title        | Mitigation                                                                  | Status |
| ------- | ----------------- | --------------------------------------------------------------------------- | ------ |
| IAM-001 | Users without MFA | Enforced deny-without-MFA policy, added users to group, verified compliance | Closed |

---

## Summary


* **Main commands to remember:**

  * `aws iam update-account-password-policy`
  * `aws iam create-policy`
  * `aws iam attach-group-policy`
  * `aws accessanalyzer create-analyzer`

* **Audit script** (`Audit-MFA.ps1`) makes compliance evidence easy.

This project shows:

* **Security as Code** → policies + scripts in GitHub
* **Compliance mindset** → risk register + evidence
* **Clear documentation** → simple enough for beginners

>Fork this repo, practice in your own AWS account, and expand it with more audits (least privilege, service control policies, etc.).
